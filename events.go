package main

// Events and notifications. A detector looks at the box every 20 seconds and records what deserves a human's attention: a device it has never seen, the uplink going down and
// coming back, encrypted DNS failing, a service dying, the box running hot, bursts of failed ssh logins, a radio dropping out, the web certificate being renewed, the data plan
// crossing a threshold, and restarts. Events are kept (newest 100, /data/proxy/events.json) and shown on the page. Optionally each event of sufficient severity is also pushed to an
// ntfy topic you choose: that is OUTWARD-FACING, so it is off until you give a URL, and what is sent is a generic sentence only (never a name, MAC, address, message or key). The
// plain /status.json carries only counts of unseen events, for an outside watcher, who can then ask the page for detail.
// Tower changes are not detected on purpose: the tower telemetry in cell.go is export only (WiGLE), not a detector.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sevInfo      = "info"
	sevAttention = "attention"
	sevAlert     = "alert"
)

func sevRank(s string) int {
	switch s {
	case sevAlert:
		return 3
	case sevAttention:
		return 2
	}
	return 1
}

type evt struct {
	ID     int    `json:"id"`
	T      int64  `json:"t"`
	Kind   string `json:"kind"`
	Sev    string `json:"sev"`
	Text   string `json:"text"`   // for the page: may name a device
	Public string `json:"public"` // generic: what may leave the house
	Seen   bool   `json:"seen"`
	Prev   string `json:"prev,omitempty"` // the hash of the event before this one (the chain, see eventChain)
	Hash   string `json:"hash,omitempty"` // sha256 over prev, id, time, kind, severity and both texts; never over Seen, which the page changes
}

// The event log is a hash chain: every event stored carries the hash of the one before it, and the file keeps the hash of the last event it dropped off the front, so a
// gap, an edit, a reordering or a truncation anywhere in the kept log breaks the chain and the page and the diagnostics say so and where. Honest limit: there is no secret
// in it, so someone with a root shell on the box can rewrite the whole file, hashes and all; it defends against partial edits, corruption and silent loss, and it gives a
// head hash that a companion computer can copy off the box (it is in /api/events) and compare later, which is the only real tamper evidence a single box can offer.
func eventHash(prev string, e evt) string {
	h := sha256.Sum256([]byte(prev + "|" + strconv.Itoa(e.ID) + "|" + strconv.FormatInt(e.T, 10) + "|" + e.Kind + "|" + e.Sev + "|" + e.Text + "|" + e.Public))
	return hex.EncodeToString(h[:])
}

type eventChain struct {
	OK       bool   `json:"ok"`
	Length   int    `json:"length"`              // hashed events in the kept log
	Since    int64  `json:"since,omitempty"`     // when the chain started (the oldest hashed event, or the clear that began it)
	Head     string `json:"head,omitempty"`      // the newest event's hash: copy it somewhere else to compare later
	BrokenAt int    `json:"broken_at,omitempty"` // the id of the first event whose link does not hold
}

// verifyChain walks the kept events: each hashed one must carry the previous hash (base for the oldest) and its own correct hash. Events from before the chain existed
// (no hash) are tolerated only at the front.
func verifyChain(base string, es []evt) eventChain {
	c := eventChain{OK: true}
	prev := base
	for _, e := range es {
		if e.Hash == "" {
			if c.Length == 0 {
				continue // an event from before the chain existed, in front of it
			}
			c.OK, c.BrokenAt = false, e.ID
			return c
		}
		if e.Prev != prev || eventHash(e.Prev, e) != e.Hash {
			c.OK, c.BrokenAt = false, e.ID
			return c
		}
		if c.Length == 0 {
			c.Since = e.T
		}
		c.Length++
		prev = e.Hash
		c.Head = e.Hash
	}
	return c
}

type eventsFileV2 struct {
	Format string `json:"format"` // "orbic-events-2"
	Base   string `json:"base"`   // the hash of the last event dropped off the front; "" when none has been
	Since  int64  `json:"since"`  // when this chain began
	Events []evt  `json:"events"`
}

type devObs struct{ MAC, IP, Band, Host string }

type evIn struct {
	Now          time.Time
	Online       []devObs
	UplinkOK     bool
	UplinkFails  int
	DoHDown      bool
	ServicesDown []string
	TempMax      float64
	SSHFailed    int
	Wifi24Down   bool
	Wifi5Down    bool // only set when the 5 GHz network is switched on
	CertFP       string
	BudgetPct    float64 // 0 when there is no cap
	SysUptime    float64
}

// detector is the state machine behind the events: pure given its inputs, so every rule is unit-tested.
type detector struct {
	started    bool
	known      map[string]bool
	upDownAt   time.Time
	uplinkDown bool
	dohFB      bool
	svcCount   map[string]int
	svcAlerted map[string]bool
	hotCount   int
	hot        bool
	sshBase    int
	radioCount int
	radioDown  bool
	certFP     string
	budgetLvl  int
	lastUp     float64
	knownSaved bool
}

func newDetector(known map[string]bool) *detector {
	if known == nil {
		known = map[string]bool{}
	}
	return &detector{known: known, svcCount: map[string]int{}, svcAlerted: map[string]bool{}}
}

func mk(kind, sev, text, public string, now time.Time) evt {
	return evt{T: now.Unix(), Kind: kind, Sev: sev, Text: text, Public: public}
}

func (d *detector) step(in evIn) []evt {
	var out []evt
	now := in.Now
	if !d.started {
		d.started = true
		for _, o := range in.Online {
			d.known[o.MAC] = true // the devices already here are not "new": seed silently
		}
		d.certFP, d.sshBase, d.lastUp = in.CertFP, in.SSHFailed, in.SysUptime
		d.uplinkDown = !in.UplinkOK && in.UplinkFails >= 3
		d.dohFB = in.DoHDown
		msg := "The web page and proxy started"
		if in.SysUptime < 900 {
			msg = "The Orbic restarted"
		}
		return append(out, mk("restart", sevInfo, msg, msg, now))
	}
	if in.SysUptime+30 < d.lastUp { // the whole box restarted while we kept running (cannot normally happen) or the counter wrapped
		out = append(out, mk("restart", sevInfo, "The Orbic restarted", "The Orbic restarted", now))
	}
	d.lastUp = in.SysUptime
	for _, o := range in.Online {
		if d.known[o.MAC] {
			continue
		}
		d.known[o.MAC] = true
		who := o.Host
		if who == "" {
			who = "unnamed"
		}
		out = append(out, mk("new_device", sevAttention, fmt.Sprintf("A new device joined: %s (%s, %s, %s)", who, o.MAC, o.IP, orStr(o.Band, "wired")), "A new device joined the network", now))
	}
	switch down := !in.UplinkOK && in.UplinkFails >= 3; {
	case down && !d.uplinkDown:
		d.uplinkDown, d.upDownAt = true, now
		out = append(out, mk("uplink_down", sevAlert, "The internet is down: the cellular uplink has stopped answering", "The Orbic's internet connection is down", now))
	case !down && d.uplinkDown && in.UplinkOK:
		d.uplinkDown = false
		dur := now.Sub(d.upDownAt).Round(time.Minute)
		out = append(out, mk("uplink_up", sevInfo, fmt.Sprintf("The internet is back after about %d minute(s)", int(dur.Minutes())), "The Orbic's internet connection is back", now))
	}
	switch {
	case in.DoHDown && !d.dohFB:
		d.dohFB = true
		out = append(out, mk("doh_down", sevAttention, "Encrypted DNS is failing: name lookups are being refused, and nothing is sent in the clear", "Encrypted DNS is failing on the Orbic", now))
	case !in.DoHDown && d.dohFB:
		d.dohFB = false
		out = append(out, mk("doh_ok", sevInfo, "Encrypted DNS is working again", "Encrypted DNS is working again", now))
	}
	cur := map[string]bool{}
	for _, s := range in.ServicesDown {
		cur[s] = true
		d.svcCount[s]++
		if d.svcCount[s] >= 2 && !d.svcAlerted[s] {
			d.svcAlerted[s] = true
			out = append(out, mk("service_down", sevAlert, "A service stopped: "+s, "A service on the Orbic stopped", now))
		}
	}
	for s := range d.svcCount {
		if !cur[s] {
			if d.svcAlerted[s] {
				out = append(out, mk("service_up", sevInfo, "A service is back: "+s, "A service on the Orbic is back", now))
			}
			delete(d.svcCount, s)
			delete(d.svcAlerted, s)
		}
	}
	if in.TempMax >= 70 {
		d.hotCount++
		if d.hotCount >= 2 && !d.hot {
			d.hot = true
			out = append(out, mk("hot", sevAttention, fmt.Sprintf("The Orbic is running hot: %.0f°C", in.TempMax), "The Orbic is running hot", now))
		}
	} else if in.TempMax < 65 {
		d.hotCount = 0
		if d.hot {
			d.hot = false
			out = append(out, mk("cool", sevInfo, "The Orbic has cooled down", "The Orbic has cooled down", now))
		}
	}
	if in.SSHFailed < d.sshBase {
		d.sshBase = in.SSHFailed // the log restarted with a reboot
	}
	if n := in.SSHFailed - d.sshBase; n >= 5 {
		d.sshBase = in.SSHFailed
		out = append(out, mk("ssh_failed", sevAttention, fmt.Sprintf("%d failed ssh logins in a short time: see the SSH card", n), "Several failed ssh logins on the Orbic", now))
	}
	if in.Wifi24Down || in.Wifi5Down {
		d.radioCount++
		if d.radioCount >= 2 && !d.radioDown {
			d.radioDown = true
			out = append(out, mk("radio_down", sevAlert, "A Wi-Fi radio is down", "A Wi-Fi radio on the Orbic is down", now))
		}
	} else {
		d.radioCount = 0
		if d.radioDown {
			d.radioDown = false
			out = append(out, mk("radio_up", sevInfo, "The Wi-Fi radios are back", "The Wi-Fi radios are back", now))
		}
	}
	if in.CertFP != "" && d.certFP != "" && in.CertFP != d.certFP {
		out = append(out, mk("cert_renewed", sevInfo, "The web page certificate was renewed (browsers will ask to trust it again)", "The Orbic's web certificate was renewed", now))
	}
	if in.CertFP != "" {
		d.certFP = in.CertFP
	}
	lvl := 0
	switch {
	case in.BudgetPct >= 100:
		lvl = 100
	case in.BudgetPct >= 80:
		lvl = 80
	}
	if lvl > d.budgetLvl {
		sev := sevAttention
		if lvl == 100 {
			sev = sevAlert
		}
		out = append(out, mk("plan", sev, fmt.Sprintf("The data plan is %.0f%% used", in.BudgetPct), fmt.Sprintf("The data plan is over %d%% used", lvl), now))
	}
	if in.BudgetPct < 80 {
		lvl = 0
	}
	d.budgetLvl = lvl
	return out
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---- the store ----

type notifyCfg struct {
	URL     string `json:"url"`
	Min     string `json:"min"` // info | attention | alert
	Enabled bool   `json:"enabled"`
}

type eventStore struct {
	mu      sync.Mutex
	path    string
	cfgPath string
	known   string
	events  []evt
	base    string // the hash of the last event dropped off the front of the kept log (the chain's anchor)
	since   int64  // when the current chain began
	next    int
	cfg     notifyCfg
	sent    []time.Time          // when notifications went out (rate limit)
	lastOf  map[string]time.Time // per kind, for the cool-down
	lastErr string
	post    func(u, title, body string, prio int) error
	now     func() time.Time
	sink    func(evt) // called for each new event once it is stored (the export feed: stream, syslog, MQTT)
}

func newEventStore() *eventStore {
	s := &eventStore{path: *eventsFile, cfgPath: *notifyFile, known: *knownFile, lastOf: map[string]time.Time{}, now: time.Now, post: postNtfy}
	if b, err := os.ReadFile(s.path); err == nil {
		var f eventsFileV2
		if json.Unmarshal(b, &f) == nil && f.Format == "orbic-events-2" {
			s.events, s.base, s.since = f.Events, f.Base, f.Since
		} else {
			json.Unmarshal(b, &s.events) // the older file: a bare array, nothing hashed yet; the chain starts with the next event
		}
	}
	for _, e := range s.events {
		if e.ID >= s.next {
			s.next = e.ID + 1
		}
	}
	if b, err := os.ReadFile(s.cfgPath); err == nil {
		json.Unmarshal(b, &s.cfg)
	}
	if s.cfg.Min == "" {
		s.cfg.Min = sevAttention
	}
	return s
}

func (s *eventStore) saveEvents() {
	b, _ := json.Marshal(eventsFileV2{Format: "orbic-events-2", Base: s.base, Since: s.since, Events: s.events})
	writeFileAtomic(s.path, b, 0o600)
}

// head is the hash the next event must carry: the newest hashed event's, else the base; called with the lock held.
func (s *eventStore) head() string {
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Hash != "" {
			return s.events[i].Hash
		}
	}
	return s.base
}

// Chain verifies the kept log.
func (s *eventStore) Chain() eventChain {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := verifyChain(s.base, s.events)
	if s.since != 0 {
		c.Since = s.since
	}
	return c
}

// Add records events and pushes the ones that qualify.
func (s *eventStore) Add(es []evt) {
	if len(es) == 0 {
		return
	}
	s.mu.Lock()
	var push []evt
	for _, e := range es {
		e.ID = s.next
		s.next++
		if e.T == 0 {
			e.T = s.now().Unix()
		}
		e.Prev = s.head()
		e.Hash = eventHash(e.Prev, e)
		if s.since == 0 {
			s.since = e.T
		}
		s.events = append(s.events, e)
		if s.cfg.Enabled && s.cfg.URL != "" && sevRank(e.Sev) >= sevRank(s.cfg.Min) && s.allow(e) {
			push = append(push, e)
		}
	}
	if len(s.events) > 100 {
		if h := s.events[len(s.events)-101].Hash; h != "" {
			s.base = h // the dropped event's hash anchors what is kept
		}
		s.events = s.events[len(s.events)-100:]
	}
	s.saveEvents()
	u := s.cfg.URL
	added := append([]evt{}, s.events[len(s.events)-min(len(es), len(s.events)):]...)
	s.mu.Unlock()
	if s.sink != nil {
		for _, e := range added {
			s.sink(e)
		}
	}
	for _, e := range push {
		prio := 3
		if e.Sev == sevAlert {
			prio = 4
		} else if e.Sev == sevInfo {
			prio = 2
		}
		if err := s.post(u, "Orbic", e.Public, prio); err != nil {
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
			log.Printf("notification failed: %v", err)
		} else {
			s.mu.Lock()
			s.lastErr = ""
			s.mu.Unlock()
		}
	}
}

// allow enforces the cool-down per kind (10 minutes) and at most 20 pushes an hour; called with the lock held.
func (s *eventStore) allow(e evt) bool {
	now := s.now()
	if t, ok := s.lastOf[e.Kind]; ok && now.Sub(t) < 10*time.Minute && e.Kind != "uplink_up" {
		return false
	}
	var keep []time.Time
	for _, t := range s.sent {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	s.sent = keep
	if len(s.sent) >= 20 {
		return false
	}
	s.sent = append(s.sent, now)
	s.lastOf[e.Kind] = now
	return true
}

func (s *eventStore) MarkSeen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.events {
		s.events[i].Seen = true
	}
	s.saveEvents()
}

// MarkSeenKinds marks only the events of the given kinds as seen (an empty list marks every event, as MarkSeen does). It returns how many it changed.
func (s *eventStore) MarkSeenKinds(kinds []string) int {
	if len(kinds) == 0 {
		s.MarkSeen()
		return -1
	}
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for i := range s.events {
		if want[s.events[i].Kind] && !s.events[i].Seen {
			s.events[i].Seen = true
			n++
		}
	}
	s.saveEvents()
	return n
}

// Clear empties the log and begins a new chain whose first link says so, so a cleared log is never mistaken for a wiped one.
func (s *eventStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	s.events, s.base, s.since = nil, "", now
	e := evt{ID: s.next, T: now, Kind: "events_cleared", Sev: sevInfo, Text: "The events log was cleared from the page; the hash chain starts again here", Public: "The events log was cleared"}
	s.next++
	e.Hash = eventHash("", e)
	s.events = []evt{e}
	s.saveEvents()
}

type notifyView struct {
	Enabled bool   `json:"enabled"`
	URLSet  bool   `json:"url_set"`
	Where   string `json:"where,omitempty"` // host only: the topic is a secret
	Min     string `json:"min"`
	LastErr string `json:"last_error,omitempty"`
}

type eventsView struct {
	Events []evt      `json:"events"`
	Unseen int        `json:"unseen"`
	Notify notifyView `json:"notify"`
	Chain  eventChain `json:"chain"`
}

func (s *eventStore) View() eventsView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := eventsView{Events: []evt{}}
	for i := len(s.events) - 1; i >= 0; i-- {
		v.Events = append(v.Events, s.events[i])
		if !s.events[i].Seen && sevRank(s.events[i].Sev) >= 2 {
			v.Unseen++
		}
	}
	v.Notify = notifyView{Enabled: s.cfg.Enabled, URLSet: s.cfg.URL != "", Min: s.cfg.Min, LastErr: s.lastErr}
	v.Chain = verifyChain(s.base, s.events)
	if s.since != 0 {
		v.Chain.Since = s.since
	}
	if u, err := url.Parse(s.cfg.URL); err == nil && s.cfg.URL != "" {
		v.Notify.Where = u.Host
	}
	return v
}

// Counts is what the unauthenticated status feed may carry: how many events need attention, and when the last one was.
func (s *eventStore) Counts() (unseen int, last int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if sevRank(e.Sev) >= 2 && !e.Seen {
			unseen++
		}
		if sevRank(e.Sev) >= 2 && e.T > last {
			last = e.T
		}
	}
	return
}

// validNtfyURL accepts https URLs, and http only for a private or loopback address (a self-hosted ntfy on the LAN). No credentials in the URL, a topic path required.
func validNtfyURL(raw string) error {
	if len(raw) > 200 {
		return errors.New("the address is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("that is not a web address like https://ntfy.sh/your-secret-topic")
	}
	if u.User != nil {
		return errors.New("put no user name or password in the address")
	}
	if strings.Trim(u.Path, "/") == "" {
		return errors.New("the address needs a topic: https://ntfy.sh/your-secret-topic")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
			return errors.New("plain http is only allowed to an address on your own network")
		}
	default:
		return errors.New("the address must start with https://")
	}
	return nil
}

func (s *eventStore) SetNotify(c notifyCfg) error {
	c.URL = strings.TrimSpace(c.URL)
	if c.Min != sevInfo && c.Min != sevAttention && c.Min != sevAlert {
		return errors.New("the level must be info, attention or alert")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.URL == "" {
		c.URL = s.cfg.URL // a blank box keeps the stored address (it is never shown back)
	} else if err := validNtfyURL(c.URL); err != nil {
		return err
	}
	if c.Enabled && c.URL == "" {
		return errors.New("give the ntfy address first")
	}
	s.cfg = c
	b, _ := json.Marshal(c)
	return writeFileAtomic(s.cfgPath, b, 0o600)
}

func (s *eventStore) ClearNotifyURL() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = notifyCfg{Min: sevAttention}
	b, _ := json.Marshal(s.cfg)
	return writeFileAtomic(s.cfgPath, b, 0o600)
}

func (s *eventStore) Test() error {
	s.mu.Lock()
	u := s.cfg.URL
	s.mu.Unlock()
	if u == "" {
		return errors.New("give the ntfy address first")
	}
	return s.post(u, "Orbic", "A test notification from the Orbic", 3)
}

// postNtfy sends one notification the way ntfy expects: the body is the message, headers carry the title and priority. It goes out through our own dialler and root set.
func postNtfy(u, title, body string, prio int) error {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return dialUpstream(ctx, n, a) }}}
	req, err := http.NewRequest("POST", u, bytes.NewReader([]byte(body)))
	if err != nil {
		return errors.New("bad address")
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", strconv.Itoa(prio))
	req.Header.Set("Tags", "satellite_antenna")
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("could not reach the notification server")
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the notification server answered %d", resp.StatusCode)
	}
	return nil
}

// ---- the loop ----

func loadKnown(path string) map[string]bool {
	m := map[string]bool{}
	var l []string
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &l) == nil {
		for _, x := range l {
			m[x] = true
		}
	}
	return m
}

func saveKnown(path string, m map[string]bool) {
	var l []string
	for k := range m {
		l = append(l, k)
	}
	sort.Strings(l)
	b, _ := json.Marshal(l)
	writeFileAtomic(path, b, 0o600)
}

func gatherEvIn() evIn {
	now := time.Now()
	in := evIn{Now: now, TempMax: maxTemp(), SysUptime: procFloat("/proc/uptime", 0)}
	for _, d := range gatherDevices() {
		if d.Online {
			in.Online = append(in.Online, devObs{MAC: d.MAC, IP: d.IP, Band: d.Band, Host: orStr(d.Label, orStr(d.Name, d.Hostname))})
		}
	}
	uplinkMu.Lock()
	in.UplinkOK, in.UplinkFails = uplink.OK, uplink.Fails
	uplinkMu.Unlock()
	if dnsProxy != nil {
		in.DoHDown = dnsProxy.Up.Failing()
	}
	comms, stopped, lines := scanProcs("/proc")
	on5 := false
	if wifi != nil {
		raw, _ := os.ReadFile(wifi.env.xmlPath)
		on5 = parseWifiSettings(string(raw)).Five.Enabled
		in.Wifi24Down = wifi.env.hostapdState() != "ENABLED"
		in.Wifi5Down = on5 && wifi.env.hostapdState5 != nil && wifi.env.hostapdState5() != "ENABLED"
	}
	for _, sv := range serviceTable(comms, stopped, lines) {
		if sv.State == "running" || sv.State == "held" || (strings.HasPrefix(sv.Name, "hostapd, 5") && !on5) {
			continue
		}
		in.ServicesDown = append(in.ServicesDown, strings.Fields(sv.Name)[0])
	}
	if sshMgr != nil {
		in.SSHFailed = sshMgr.View().Summary.Failed
	}
	if certMgr != nil {
		in.CertFP = certMgr.Fingerprint()
	}
	if *capGB > 0 {
		usageMu.Lock()
		u := usage
		usageMu.Unlock()
		in.BudgetPct = 100 * float64(u.Down+u.Up) / (*capGB * 1e9)
	}
	return in
}

func eventLoop() {
	det := newDetector(loadKnown(events.known))
	for {
		es := det.step(gatherEvIn())
		saveNew := false
		for _, e := range es {
			if e.Kind == "new_device" {
				saveNew = true
			}
		}
		if saveNew || !det.knownSaved {
			saveKnown(events.known, det.known)
			det.knownSaved = true
		}
		events.Add(es)
		time.Sleep(20 * time.Second)
	}
}

var events *eventStore
