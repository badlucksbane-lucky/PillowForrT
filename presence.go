package main

// Presence: when each device arrives on the network and when it leaves, who is here now and since when, and when a device was last seen. Two signals feed it: the radio (the
// stations associated on either band, authoritative and immediate; plus neighbours the kernel still calls reachable, for anything not on Wi-Fi) every 20 seconds, and dnsmasq's
// own hook, which says the instant a lease is handed out and what the device calls itself (host name and DHCP vendor class, e.g. "android-dhcp-14", a hint at what kind of device
// it is). A device is "left" only after two checks in a row (about 40 seconds) without it, so a phone dozing its radio does not flap. Arrivals and departures are NOT events for
// every device (phones come and go all day): only the devices you choose to "watch" raise an event, at attention level, so a push can reach you ("the kids' tablet just arrived").
// Everything else is shown on the Devices card: here since, or last seen. The state is kept in /data/proxy/presence.json (written at most every 5 minutes).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type presDev struct {
	LastSeen int64  `json:"last_seen,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Host     string `json:"host,omitempty"`
	Watched  bool   `json:"watched,omitempty"`
	Since    int64  `json:"since,omitempty"` // here since (kept across restarts of tinyfwd while the device stays)
	// runtime only
	online bool
	miss   int
}

type presenceStore struct {
	mu      sync.Mutex
	path    string
	devs    map[string]*presDev
	seeded  bool
	dirty   bool
	savedAt time.Time
	now     func() time.Time
	nameOf  func(mac string) string
	emit    func(evt)
}

func newPresenceStore() *presenceStore {
	p := &presenceStore{path: *presenceFile, devs: map[string]*presDev{}, now: time.Now,
		nameOf: func(mac string) string {
			if devMgr != nil {
				if n := devMgr.All()[mac]; n.Label != "" {
					return n.Label
				}
			}
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					if r.MAC == mac {
						return r.Name
					}
				}
			}
			return ""
		},
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		}}
	if b, err := os.ReadFile(p.path); err == nil {
		json.Unmarshal(b, &p.devs)
	}
	if p.devs == nil {
		p.devs = map[string]*presDev{}
	}
	return p
}

func (p *presenceStore) dev(mac string) *presDev {
	d := p.devs[mac]
	if d == nil {
		d = &presDev{}
		p.devs[mac] = d
	}
	return d
}

// Who is the name the page shows for a device (label, host name, else the MAC), for callers outside the store.
func (p *presenceStore) Who(mac string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.who(mac)
}

func (p *presenceStore) who(mac string) string {
	d := p.devs[mac]
	if n := p.nameOf(mac); n != "" {
		return n
	}
	if d != nil && d.Host != "" {
		return d.Host
	}
	return mac
}

func (p *presenceStore) maybeSave(force bool) {
	if !p.dirty || (!force && p.now().Sub(p.savedAt) < 5*time.Minute) {
		return
	}
	b, _ := json.Marshal(p.devs)
	if writeFileAtomic(p.path, b, 0o600) == nil {
		p.dirty, p.savedAt = false, p.now()
	}
}

func human(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "a minute"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("%.0f hours", d.Hours())
}

// Observe takes the set of MACs present right now (every 20 s) and returns the events for watched devices.
func (p *presenceStore) Observe(present map[string]bool) []evt {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var out []evt
	if !p.seeded {
		p.seeded = true
		for mac := range present { // those already here are not arrivals
			d := p.dev(mac)
			if d.Since == 0 || now.Unix()-d.LastSeen > 600 { // not here a few minutes ago: a restart of tinyfwd is not an arrival, but a long absence is a fresh start
				d.Since = now.Unix()
			}
			d.online, d.LastSeen, d.miss = true, now.Unix(), 0
		}
		for mac, d := range p.devs { // anything saved as "here" that is not: it left while we were not looking
			if !present[mac] {
				d.Since = 0
			}
		}
		p.dirty = true
		p.maybeSave(false)
		return nil
	}
	for mac := range present {
		d := p.dev(mac)
		if !d.online {
			d.online, d.Since = true, now.Unix()
			p.dirty = true
			if d.Watched {
				out = append(out, p.mkEvt("device_arrived", fmt.Sprintf("%s arrived", p.who(mac)), "A watched device arrived", now))
			}
		}
		if now.Unix()-d.LastSeen > 60 {
			p.dirty = true
		}
		d.LastSeen, d.miss = now.Unix(), 0
	}
	for mac, d := range p.devs {
		if d.online && !present[mac] {
			if d.miss++; d.miss >= 2 {
				was := d.Since
				d.online, d.Since, p.dirty = false, 0, true
				if d.Watched {
					out = append(out, p.mkEvt("device_left", fmt.Sprintf("%s left (it had been here %s)", p.who(mac), human(now.Sub(time.Unix(was, 0)))), "A watched device left", now))
				}
			}
		}
	}
	p.maybeSave(false)
	return out
}

func (p *presenceStore) mkEvt(kind, text, public string, now time.Time) evt {
	return evt{T: now.Unix(), Kind: kind, Sev: sevAttention, Text: text, Public: public}
}

var (
	hookMACRe    = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	hookHostRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{0,63}$`)
	hookVendorRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/()-]{0,60}$`)
)

// Hook is dnsmasq saying a lease was handed out (add), renewed (old) or ended (del). Only add counts as an arrival (it is the first time the device asked), and the hook also
// teaches us the device's host name and vendor class.
func (p *presenceStore) Hook(op, mac, ip, host, vendor string) ([]evt, error) {
	mac = strings.ToLower(mac)
	switch op {
	case "add", "old", "del", "tftp":
	default:
		return nil, errors.New("unknown event")
	}
	if !hookMACRe.MatchString(mac) || !hookHostRe.MatchString(host) || !hookVendorRe.MatchString(vendor) {
		return nil, errors.New("bad field")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.dev(mac)
	learned := false // what a device calls itself changes rarely, so it is saved at once (the throttle is for the every-20-seconds presence updates)
	if host != "" && d.Host != host {
		d.Host, p.dirty, learned = host, true, true
	}
	if vendor != "" && d.Vendor != vendor {
		d.Vendor, p.dirty, learned = vendor, true, true
	}
	var out []evt
	if op == "add" {
		now := p.now()
		if p.seeded && !d.online {
			d.online, d.Since, d.miss = true, now.Unix(), 0
			if d.Watched {
				out = append(out, p.mkEvt("device_arrived", fmt.Sprintf("%s arrived (it just got an address)", p.who(mac)), "A watched device arrived", now))
			}
		}
		d.LastSeen, p.dirty = now.Unix(), true
	}
	p.maybeSave(learned)
	return out, nil
}

func (p *presenceStore) SetWatch(mac string, on bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !hookMACRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, d := range p.devs {
		if d.Watched {
			n++
		}
	}
	if on && !p.dev(mac).Watched && n >= 32 {
		return errors.New("too many watched devices (32 is the limit)")
	}
	p.dev(mac).Watched, p.dirty = on, true
	p.maybeSave(true)
	return nil
}

// Info is what the Devices card shows for one device.
type presInfo struct {
	Online   bool
	Since    int64
	LastSeen int64
	Vendor   string
	Watched  bool
}

func (p *presenceStore) Info() map[string]presInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]presInfo{}
	for mac, d := range p.devs {
		out[mac] = presInfo{Online: d.online, Since: d.Since, LastSeen: d.LastSeen, Vendor: d.Vendor, Watched: d.Watched}
	}
	return out
}

// gatherPresent: the stations on either band plus neighbours the kernel has heard from lately; the Orbic's own addresses are never "a device".
func gatherPresent() map[string]bool {
	present := map[string]bool{}
	if wifi != nil {
		for _, s := range parseStations(wifi.env.stations()) {
			present[s.MAC] = true
		}
	}
	out, _ := run("ip", "-4", "neigh", "show", "dev", "bridge0")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		state := f[len(f)-1]
		if state != "REACHABLE" && state != "DELAY" && state != "PROBE" && state != "PERMANENT" {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				present[strings.ToLower(f[i+1])] = true
			}
		}
	}
	if b, err := os.ReadFile("/sys/class/net/bridge0/address"); err == nil {
		delete(present, strings.ToLower(strings.TrimSpace(string(b))))
	}
	return present
}

func presenceLoop() {
	for {
		for _, e := range presence.Observe(gatherPresent()) {
			if events != nil {
				events.Add([]evt{e})
			}
		}
		time.Sleep(20 * time.Second)
	}
}

var presence *presenceStore

// handleDHCPHook receives dnsmasq's notification from the Orbic itself: loopback only, POST, and the beat token (the same one the heartbeat uses).
func handleDHCPHook(w http.ResponseWriter, r *http.Request) {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if r.Method != http.MethodPost || (host != "127.0.0.1" && host != "[::1]") || !tokenOK(r) || presence == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	if r.ParseForm() != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	v := func(k string) string { s, _ := url.QueryUnescape(r.PostForm.Get(k)); return strings.TrimSpace(s) }
	es, err := presence.Hook(v("op"), v("mac"), v("ip"), v("host"), v("vendor"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, e := range es {
		if events != nil {
			events.Add([]evt{e})
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
