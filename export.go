package main

// Export: the box as a sensor for tools you already run. Nothing here is on until you switch it on from the page, and every destination must be an address on your own
// network (an IP literal that is private or loopback: never a public host, never a name, so nothing is resolved and nothing leaves the house).
//
//   - /api/events/stream: the event log as newline-delimited JSON in the shape of Suricata's EVE log (one "alert" record per event), so Wazuh, Graylog, Loki, Vector,
//     Elastic, Splunk and anything else with an EVE parser reads it with no custom code. `?since=<id>` returns the kept events after that id; `?follow=1` keeps the
//     connection open and writes each new event as it happens. Behind the login (or the script token) like every /api path; through the onion door only the generic
//     sentence is sent, never the text that may name a device.
//   - syslog: the same events forwarded as RFC 5424 messages over UDP to a collector on the LAN (rsyslog, syslog-ng, Graylog, a SIEM), with the event's id, kind,
//     severity and chain hash as structured data so a collector keeps the chain verifiable. Off until an address is given.
//   - the packet tap (tap.go) and Home Assistant over MQTT (hass.go) read their settings from the same file.
//
// Settings: /data/proxy/export.json, mode 0600 (it may hold an MQTT password, which is never shown back and is not part of a backup snapshot, like the other identity).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type exportSyslog struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`             // ip:port on the LAN, UDP
	Public  bool   `json:"public,omitempty"` // send the generic sentence instead of the page text
}

type exportTap struct {
	Enabled bool `json:"enabled"`
}

type exportMQTT struct {
	Enabled      bool   `json:"enabled"`
	Addr         string `json:"addr"` // ip:port on the LAN, plain MQTT 3.1.1
	User         string `json:"user,omitempty"`
	Pass         string `json:"pass,omitempty"`
	NodeID       string `json:"node_id,omitempty"`       // the id Home Assistant knows this box by (default "box")
	Prefix       string `json:"prefix,omitempty"`        // topic prefix (default "pillowforrt")
	Control      bool   `json:"control,omitempty"`       // let Home Assistant pause a device's internet (a switch per device)
	PauseMinutes int    `json:"pause_minutes,omitempty"` // how long a pause from Home Assistant lasts (default 60)
}

type exportCfg struct {
	Syslog exportSyslog `json:"syslog"`
	Tap    exportTap    `json:"tap"`
	MQTT   exportMQTT   `json:"mqtt"`
}

type exportStore struct {
	mu   sync.Mutex
	path string
	cfg  exportCfg
	// runtime
	syslogErr string
	mqttState string // "off", "connecting", "connected", or an error
	mqttAt    int64
	tapActive bool
	tapLast   int64
	dial      func(network, addr string) (net.Conn, error)
}

func newExportStore(path string) *exportStore {
	s := &exportStore{path: path, dial: func(n, a string) (net.Conn, error) { return net.DialTimeout(n, a, 5*time.Second) }}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &s.cfg)
	}
	s.mqttState = "off"
	return s
}

func (s *exportStore) Cfg() exportCfg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *exportStore) save() error {
	b, _ := json.MarshalIndent(s.cfg, "", " ")
	return writeFileAtomic(s.path, b, 0o600)
}

// lanAddr accepts "ip:port" where ip is a private or loopback IPv4/IPv6 literal. Names are refused on purpose: nothing here resolves anything, and a name could point
// anywhere tomorrow.
func lanAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("give an address like 192.168.1.20:514")
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", errors.New("the address needs a port, like 192.168.1.20:514")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("use an IP address, not a name")
	}
	if !(ip.IsPrivate() || ip.IsLoopback()) {
		return "", errors.New("only an address on your own network is allowed")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", errors.New("the port must be between 1 and 65535")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(p)), nil
}

var topicOK = func(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// SetSyslog validates and stores the syslog target.
func (s *exportStore) SetSyslog(c exportSyslog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Enabled || c.Addr != "" {
		a, err := lanAddr(c.Addr)
		if err != nil {
			return err
		}
		c.Addr = a
	}
	s.cfg.Syslog = c
	s.syslogErr = ""
	return s.save()
}

func (s *exportStore) SetTap(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Tap.Enabled = on
	return s.save()
}

// SetMQTT validates and stores the broker settings; an empty password keeps the saved one.
func (s *exportStore) SetMQTT(c exportMQTT) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Enabled || c.Addr != "" {
		a, err := lanAddr(c.Addr)
		if err != nil {
			return err
		}
		c.Addr = a
	}
	if c.NodeID == "" {
		c.NodeID = "box"
	}
	if c.Prefix == "" {
		c.Prefix = "pillowforrt"
	}
	if !topicOK(c.NodeID) || !topicOK(c.Prefix) {
		return errors.New("the node id and prefix may only use a-z, 0-9, _ and - (40 characters at most)")
	}
	if len(c.User) > 100 || len(c.Pass) > 200 {
		return errors.New("the user name or password is too long")
	}
	if c.Pass == "" {
		c.Pass = s.cfg.MQTT.Pass
	}
	if c.PauseMinutes <= 0 {
		c.PauseMinutes = 60
	}
	if c.PauseMinutes > 24*60 {
		c.PauseMinutes = 24 * 60
	}
	s.cfg.MQTT = c
	return s.save()
}

func (s *exportStore) ClearMQTTPass() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.MQTT.Pass = ""
	return s.save()
}

type exportView struct {
	Syslog struct {
		Enabled bool   `json:"enabled"`
		Addr    string `json:"addr"`
		Public  bool   `json:"public"`
		LastErr string `json:"last_error,omitempty"`
	} `json:"syslog"`
	Tap struct {
		Enabled bool  `json:"enabled"`
		Active  bool  `json:"active"`
		Last    int64 `json:"last,omitempty"`
	} `json:"tap"`
	MQTT struct {
		Enabled      bool   `json:"enabled"`
		Addr         string `json:"addr"`
		User         string `json:"user"`
		PassSet      bool   `json:"pass_set"`
		NodeID       string `json:"node_id"`
		Prefix       string `json:"prefix"`
		Control      bool   `json:"control"`
		PauseMinutes int    `json:"pause_minutes"`
		State        string `json:"state"`
		StateAt      int64  `json:"state_at,omitempty"`
	} `json:"mqtt"`
	Stream struct {
		Head int `json:"head"` // the newest event id, so a collector knows where to resume
	} `json:"stream"`
}

func (s *exportStore) View(headID int) exportView {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v exportView
	v.Syslog.Enabled, v.Syslog.Addr, v.Syslog.Public, v.Syslog.LastErr = s.cfg.Syslog.Enabled, s.cfg.Syslog.Addr, s.cfg.Syslog.Public, s.syslogErr
	v.Tap.Enabled, v.Tap.Active, v.Tap.Last = s.cfg.Tap.Enabled, s.tapActive, s.tapLast
	m := s.cfg.MQTT
	v.MQTT.Enabled, v.MQTT.Addr, v.MQTT.User, v.MQTT.PassSet = m.Enabled, m.Addr, m.User, m.Pass != ""
	v.MQTT.NodeID, v.MQTT.Prefix, v.MQTT.Control, v.MQTT.PauseMinutes = orStr(m.NodeID, "box"), orStr(m.Prefix, "pillowforrt"), m.Control, m.PauseMinutes
	if v.MQTT.PauseMinutes == 0 {
		v.MQTT.PauseMinutes = 60
	}
	v.MQTT.State, v.MQTT.StateAt = s.mqttState, s.mqttAt
	v.Stream.Head = headID
	return v
}

func (s *exportStore) setMQTTState(st string) {
	s.mu.Lock()
	s.mqttState, s.mqttAt = st, time.Now().Unix()
	s.mu.Unlock()
}

// ---- EVE records ----

type eveAlert struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

type eveStone struct {
	ID     int    `json:"id"`
	Kind   string `json:"kind"`
	Sev    string `json:"sev"`
	Text   string `json:"text,omitempty"`
	Public string `json:"public"`
	Hash   string `json:"hash,omitempty"`
	Prev   string `json:"prev,omitempty"`
}

// eveRecord is one event in the shape Suricata writes to eve.json: the common fields every EVE consumer keys on (timestamp, event_type, alert.*) plus a "stone" object
// carrying what is ours. event_type is always "alert" so a collector's existing Suricata pipeline files it with the others; the real level is alert.severity (1 alert,
// 2 to look at, 3 info) and stone.sev.
type eveRecord struct {
	Timestamp string   `json:"timestamp"`
	EventType string   `json:"event_type"`
	Host      string   `json:"host"`
	Alert     eveAlert `json:"alert"`
	Stone     eveStone `json:"stone"`
}

const eveGID = 9000 // a generator id no Suricata rule set uses

// eveSID gives each kind a stable signature id in a private range, so a collector can group and silence by kind.
func eveSID(kind string) int {
	h := fnv.New32a()
	h.Write([]byte(kind))
	return 1000000 + int(h.Sum32()%1000000)
}

func eveSeverity(sev string) int {
	switch sev {
	case sevAlert:
		return 1
	case sevAttention:
		return 2
	}
	return 3
}

func kindWords(kind string) string { return strings.ReplaceAll(kind, "_", " ") }

func toEVE(e evt, host string, public bool) eveRecord {
	r := eveRecord{Timestamp: time.Unix(e.T, 0).Format("2006-01-02T15:04:05.000000-0700"), EventType: "alert", Host: host}
	r.Alert = eveAlert{Action: "allowed", GID: eveGID, SignatureID: eveSID(e.Kind), Rev: 1, Signature: "PillowForrT: " + kindWords(e.Kind), Category: "PillowForrT " + e.Sev, Severity: eveSeverity(e.Sev)}
	r.Stone = eveStone{ID: e.ID, Kind: e.Kind, Sev: e.Sev, Public: e.Public, Hash: e.Hash, Prev: e.Prev}
	if !public {
		r.Stone.Text = e.Text
	}
	return r
}

// ---- the event stream ----

// eventFeed fans new events out to the stream's followers and the forwarders. Subscribers get a buffered channel; one that falls behind is dropped rather than
// holding the detector loop.
type eventFeed struct {
	mu   sync.Mutex
	subs map[chan evt]struct{}
}

func newEventFeed() *eventFeed { return &eventFeed{subs: map[chan evt]struct{}{}} }

func (f *eventFeed) subscribe() (chan evt, func()) {
	ch := make(chan evt, 64)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	return ch, func() {
		f.mu.Lock()
		delete(f.subs, ch)
		f.mu.Unlock()
	}
}

func (f *eventFeed) publish(e evt) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.subs {
		select {
		case ch <- e:
		default:
			delete(f.subs, ch)
			close(ch)
		}
	}
}

// Since returns the kept events with an id after `after`, oldest first.
func (s *eventStore) Since(after int) []evt {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []evt
	for _, e := range s.events {
		if e.ID > after {
			out = append(out, e)
		}
	}
	return out
}

// HeadID is the newest event's id (-1 when the log is empty).
func (s *eventStore) HeadID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return -1
	}
	return s.events[len(s.events)-1].ID
}

// serveEventStream writes EVE records as newline-delimited JSON. GET /api/events/stream?since=<id>&follow=1
func serveEventStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	public := viaOnion(r) || r.URL.Query().Get("public") == "1"
	since := -1
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "since must be an event id"})
			return
		}
		since = n
	}
	follow := r.URL.Query().Get("follow") == "1"
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fl, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	var ch chan evt
	var stop func()
	if follow {
		ch, stop = eventsFeed.subscribe() // subscribe before the backlog so nothing falls between
		defer stop()
	}
	last := since
	for _, e := range events.Since(since) {
		enc.Encode(toEVE(e, *uiHost, public))
		last = e.ID
	}
	if fl != nil {
		fl.Flush()
	}
	if !follow {
		return
	}
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return // dropped for falling behind: the client reconnects with ?since=
			}
			if e.ID <= last {
				continue
			}
			last = e.ID
			if err := enc.Encode(toEVE(e, *uiHost, public)); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}

// ---- syslog ----

// syslogLine renders one event as an RFC 5424 message. Facility local0; severity alert->1 (alert), attention->4 (warning), info->6 (informational). The structured
// data carries the chain fields so a collector that keeps every line can verify the chain on its own copy.
func syslogLine(e evt, host string, public bool) string {
	sev := 6
	switch e.Sev {
	case sevAlert:
		sev = 1
	case sevAttention:
		sev = 4
	}
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return strings.ReplaceAll(s, `]`, `\]`)
	}
	msg := e.Text
	if public || msg == "" {
		msg = e.Public
	}
	msgid := e.Kind
	if msgid == "" {
		msgid = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s tinyfwd - %s [stone@0 id=\"%d\" kind=\"%s\" sev=\"%s\" hash=\"%s\" prev=\"%s\"] %s",
		16*8+sev, time.Unix(e.T, 0).UTC().Format("2006-01-02T15:04:05Z"), host, msgid, e.ID, esc(e.Kind), esc(e.Sev), esc(e.Hash), esc(e.Prev), msg)
}

func (s *exportStore) sendSyslog(e evt) {
	s.mu.Lock()
	c := s.cfg.Syslog
	dial := s.dial
	s.mu.Unlock()
	if !c.Enabled || c.Addr == "" {
		return
	}
	conn, err := dial("udp", c.Addr)
	if err == nil {
		_, err = conn.Write([]byte(syslogLine(e, *uiHost, c.Public)))
		conn.Close()
	}
	s.mu.Lock()
	if err != nil {
		s.syslogErr = err.Error()
	} else {
		s.syslogErr = ""
	}
	s.mu.Unlock()
}

// TestSyslog sends one informational line so the collector side can be checked.
func (s *exportStore) TestSyslog() error {
	s.mu.Lock()
	c := s.cfg.Syslog
	s.mu.Unlock()
	if c.Addr == "" {
		return errors.New("give the collector's address first")
	}
	s.sendSyslog(evt{ID: 0, T: time.Now().Unix(), Kind: "test", Sev: sevInfo, Text: "test message from the PillowForrT page", Public: "test message from the PillowForrT page"})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syslogErr != "" {
		return errors.New("could not send: " + s.syslogErr)
	}
	return nil
}

// exportSink is what the event store calls for each new event: the feed for stream followers, syslog, MQTT.
func exportSink(e evt) {
	eventsFeed.publish(e)
	if exports != nil {
		go exports.sendSyslog(e)
	}
	if hass != nil {
		hass.event(e)
	}
}

// ---- API ----

func handleExportAPI(w http.ResponseWriter, r *http.Request, path string) {
	if exports == nil {
		http.Error(w, "not found", 404)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	switch {
	case path == "export" && r.Method == http.MethodGet:
		writeJSON(w, 200, exports.View(events.HeadID()))
	case path == "export/syslog" && r.Method == http.MethodPost:
		var c exportSyslog
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := exports.SetSyslog(c); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "export/syslog/test" && r.Method == http.MethodPost:
		if err := exports.TestSyslog(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "a test line was sent"})
	case path == "export/tap" && r.Method == http.MethodPost:
		var b struct{ Enabled bool }
		json.NewDecoder(r.Body).Decode(&b)
		if err := exports.SetTap(b.Enabled); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": map[bool]string{true: "the packet tap is on", false: "the packet tap is off"}[b.Enabled]})
	case path == "export/mqtt" && r.Method == http.MethodPost:
		var c exportMQTT
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := exports.SetMQTT(c); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if hass != nil {
			hass.reconnect()
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "export/mqtt/clearpass" && r.Method == http.MethodPost:
		if err := exports.ClearMQTTPass(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if hass != nil {
			hass.reconnect()
		}
		writeJSON(w, 200, map[string]string{"status": "the password was removed"})
	default:
		http.Error(w, "not found", 404)
	}
}

var (
	exports    *exportStore
	eventsFeed = newEventFeed()
)

// ctxDone is a small helper for loops that poll a context.
func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
