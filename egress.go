package main

// Outbound service allow-list (0.42.0, "hard block outbound services we do not approve"). Forwarded NEW connections from the LAN to the cellular side or to
// the Mullvad tunnel are matched against an allow-list of (protocol, ports), global or per device (by MAC). Three modes:
//   off      nothing hooked;
//   monitor  the chain only allows (everything falls through); a sampler reads the conntrack table every 10 s and tallies what would be refused, per device, so the list can
//            be built from what the house really uses before anything breaks;
//   enforce  TCP outside the list is refused with a reset, UDP with port-unreachable, other protocols with an ICMP reject. ICMP echo and the ICMPv6 types IPv6 needs always pass.
// Only the LAN-to-outside direction is policed (the web page and the LAN are never affected). Traffic that tinyfwd and Tor open from the Orbic itself (the PAC proxy, DoH,
// the tunnel) is OUTPUT, not forwarded, and is not covered here. DNS and DoT stay refused by the guard whatever this says. File: /data/proxy/egress.json.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type egressRule struct {
	Proto string `json:"proto"` // tcp | udp
	Ports string `json:"ports"` // "80,443,5228:5230"
	Note  string `json:"note,omitempty"`
}

type egressCfg struct {
	Mode     string                  `json:"mode"` // off | monitor | enforce
	Services []string                `json:"services"`
	Allow    []egressRule            `json:"allow"`
	Devices  map[string][]egressRule `json:"devices,omitempty"`      // lower-case MAC
	DevSvc   map[string][]string     `json:"dev_services,omitempty"` // extra services for one device
}

// egressService is a named bundle of ports you can tick, so nobody has to know that push notifications live on 5223.
type egressService struct {
	ID    string
	Name  string
	Desc  string
	Rules []egressRule
	On    bool // part of the starting set
}

var egressServices = []egressService{
	{"web", "Web", "Websites and most apps (HTTP and HTTPS)", []egressRule{{"tcp", "80,443", ""}}, true},
	{"quic", "QUIC / HTTP3", "Faster web for Chrome and many apps; apps fall back to normal HTTPS without it", []egressRule{{"udp", "443", ""}}, true},
	{"ntp", "Clock sync", "Network time (NTP)", []egressRule{{"udp", "123", ""}}, true},
	{"ssh", "SSH and git", "Secure shell and git over ssh", []egressRule{{"tcp", "22", ""}}, true},
	{"mail", "Email apps", "Secure IMAP, POP3 and SMTP submission", []egressRule{{"tcp", "465,587,993,995,143", ""}}, true},
	{"push", "Push notifications", "Apple and Google push services", []egressRule{{"tcp", "5222,5223,5228:5230", ""}}, true},
	{"calls", "Calls and video", "FaceTime, Google Meet and SIP signalling and STUN. Peer media on random ports will not get through", []egressRule{{"udp", "3478:3481,5060:5061,16384:16387,19302:19309", ""}, {"tcp", "5060:5061", ""}}, false},
	{"consoles", "Game consoles", "Xbox Live and PlayStation Network", []egressRule{{"tcp", "3074,3478:3480,1935", ""}, {"udp", "88,500,3074,3478:3479,3544,4500", ""}}, false},
	{"vpn", "Devices' own VPNs", "WireGuard, OpenVPN and IPsec started by a device itself (this lets a device route around the filters)", []egressRule{{"udp", "51820,1194,500,4500", ""}, {"tcp", "1194", ""}}, false},
	{"torrent", "BitTorrent", "Torrent client ports (peers on other ports cannot be allowed)", []egressRule{{"tcp", "6881:6889,51413", ""}, {"udp", "6881:6889,51413", ""}}, false},
	{"remote", "Remote desktop", "RDP and VNC", []egressRule{{"tcp", "3389,5900:5901", ""}}, false},
	{"mqtt", "MQTT and IRC", "Message brokers and chat", []egressRule{{"tcp", "1883,8883,6667,6697", ""}}, false},
}

func serviceByID(id string) (egressService, bool) {
	for _, sv := range egressServices {
		if sv.ID == id {
			return sv, true
		}
	}
	return egressService{}, false
}

// effectiveRules is everything a device (mac "" = the general rules only) may use: ticked services, global ports, and that device's own additions.
func effectiveRules(c egressCfg, mac string) []egressRule {
	var out []egressRule
	add := func(ids []string) {
		for _, id := range ids {
			if sv, ok := serviceByID(id); ok {
				out = append(out, sv.Rules...)
			}
		}
	}
	add(c.Services)
	out = append(out, c.Allow...)
	if mac != "" {
		add(c.DevSvc[mac])
		out = append(out, c.Devices[mac]...)
	}
	return out
}

type egressSeen struct {
	MAC    string   `json:"mac"`
	IP     string   `json:"ip"`
	Proto  string   `json:"proto"`
	Port   int      `json:"port"`
	Flows  int      `json:"flows"`
	Last   int64    `json:"last"`
	Dsts   []string `json:"dsts"`
	Listed bool     `json:"-"`
}

type egressMgr struct {
	mu      sync.Mutex
	file    string
	cfg     egressCfg
	seen    map[string]*egressSeen
	flows   map[string]int64         // flow tuple -> last sampled (dedupe across samples)
	arp     func() map[string]string // mac -> ip
	conn    func() string
	apply   func(rules4, rules6 string, hooked bool) error
	now     func() time.Time
	lastErr string
}

var portsRe = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?)*$`)

func defaultEgress() egressCfg {
	// The private tree starts in watch-only mode; the public export (release/scrub.py) changes this one word to "enforce".
	c := egressCfg{Mode: "enforce"}
	for _, sv := range egressServices {
		if sv.On {
			c.Services = append(c.Services, sv.ID)
		}
	}
	return c
}

func validRule(r egressRule) error {
	if r.Proto != "tcp" && r.Proto != "udp" {
		return errors.New("protocol must be tcp or udp")
	}
	if !portsRe.MatchString(r.Ports) {
		return errors.New("ports look like 80,443,5228:5230")
	}
	for _, p := range strings.FieldsFunc(r.Ports, func(c rune) bool { return c == ',' || c == ':' }) {
		if n, _ := strconv.Atoi(p); n < 1 || n > 65535 {
			return errors.New("port out of range")
		}
	}
	return nil
}

func newEgressMgr(file string) *egressMgr {
	m := &egressMgr{file: file, seen: map[string]*egressSeen{}, flows: map[string]int64{}, now: time.Now, apply: applyEgress,
		arp: func() map[string]string {
			b, _ := os.ReadFile("/proc/net/arp")
			ip2 := map[string]string{}
			for mac, ip := range parseARP(string(b)) {
				ip2[mac] = ip
			}
			return ip2
		},
		conn: func() string { b, _ := os.ReadFile("/proc/net/nf_conntrack"); return string(b) }}
	m.cfg = defaultEgress()
	if b, err := os.ReadFile(file); err == nil {
		var c egressCfg
		if json.Unmarshal(b, &c) == nil && (c.Mode == "off" || c.Mode == "monitor" || c.Mode == "enforce") {
			m.cfg = c
		}
	}
	return m
}

func (m *egressMgr) saveLocked() error {
	b, _ := json.MarshalIndent(m.cfg, "", " ")
	tmp := m.file + ".new"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.file)
}

// chunks splits a port list into groups the multiport match accepts (a range counts as two of the 15).
func portChunks(ports string) []string {
	var out []string
	var cur []string
	n := 0
	for _, p := range strings.Split(ports, ",") {
		w := 1
		if strings.Contains(p, ":") {
			w = 2
		}
		if n+w > 15 {
			out, cur, n = append(out, strings.Join(cur, ",")), nil, 0
		}
		cur, n = append(cur, p), n+w
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, ","))
	}
	return out
}

// egressRules renders the chain for iptables-restore (v6 = true: ip6tables flavour). Pure function: unit-tested.
func egressRules(c egressCfg, v6 bool) string {
	var b strings.Builder
	b.WriteString("*filter\n:HS_EGRESS - [0:0]\n")
	if v6 {
		for _, t := range []int{1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137} {
			fmt.Fprintf(&b, "-A HS_EGRESS -p icmpv6 --icmpv6-type %d -j RETURN\n", t)
		}
	} else {
		b.WriteString("-A HS_EGRESS -p icmp -j RETURN\n")
	}
	emit := func(prefix string, rs []egressRule) {
		for _, r := range rs {
			for _, ch := range portChunks(r.Ports) {
				fmt.Fprintf(&b, "-A HS_EGRESS %s-p %s -m multiport --dports %s -j RETURN\n", prefix, r.Proto, ch)
			}
		}
	}
	emit("", effectiveRules(c, ""))
	seen := map[string]bool{}
	var macs []string
	for mac := range c.Devices {
		seen[mac] = true
		macs = append(macs, mac)
	}
	for mac := range c.DevSvc {
		if !seen[mac] {
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs)
	for _, mac := range macs { // a device's own part only: the general rules above already cover everything else
		var own []egressRule
		for _, id := range c.DevSvc[mac] {
			if sv, ok := serviceByID(id); ok {
				own = append(own, sv.Rules...)
			}
		}
		emit("-m mac --mac-source "+mac+" ", append(own, c.Devices[mac]...))
	}
	if c.Mode == "enforce" {
		b.WriteString("-A HS_EGRESS -p tcp -j REJECT --reject-with tcp-reset\n")
		if v6 {
			b.WriteString("-A HS_EGRESS -p udp -j REJECT --reject-with icmp6-port-unreachable\n-A HS_EGRESS -j REJECT --reject-with icmp6-adm-prohibited\n")
		} else {
			b.WriteString("-A HS_EGRESS -p udp -j REJECT --reject-with icmp-port-unreachable\n-A HS_EGRESS -j REJECT --reject-with icmp-admin-prohibited\n")
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func applyEgress(r4, r6 string, hooked bool) error {
	for _, x := range []struct{ cmd, tool, rules string }{{"iptables-restore", "iptables", r4}, {"ip6tables-restore", "ip6tables", r6}} {
		if err := restore(x.cmd, x.rules); err != nil {
			return err
		}
		for _, o := range []string{"rmnet_data+", "mullvad0"} {
			spec := "-i bridge0 -o " + o + " -m state --state NEW -j HS_EGRESS"
			if hooked {
				run("sh", "-c", x.tool+" -C FORWARD "+spec+" 2>/dev/null || "+x.tool+" -I FORWARD 1 "+spec)
			} else {
				run("sh", "-c", "while "+x.tool+" -D FORWARD "+spec+" 2>/dev/null; do :; done")
			}
		}
	}
	return nil
}

func (m *egressMgr) Reconcile() {
	m.mu.Lock()
	c := m.cfg
	m.mu.Unlock()
	if err := m.apply(egressRules(c, false), egressRules(c, true), c.Mode != "off"); err != nil {
		m.mu.Lock()
		m.lastErr = err.Error()
		m.mu.Unlock()
		log.Printf("egress rules: %v", err)
	} else {
		m.mu.Lock()
		m.lastErr = ""
		m.mu.Unlock()
	}
}

type ctFlow struct {
	Proto, Src, Dst string
	Port            int
}

// parseConntrack returns the original-direction flows of LAN hosts to non-LAN addresses (IPv4 tcp and udp).
func parseConntrack(s string) map[string]ctFlow {
	out := map[string]ctFlow{}
	_, lan, _ := net.ParseCIDR(lanCIDR)
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 8 || f[0] != "ipv4" || (f[2] != "tcp" && f[2] != "udp") {
			continue
		}
		kv := map[string]string{}
		for _, w := range f[4:] {
			if i := strings.IndexByte(w, '='); i > 0 {
				if _, dup := kv[w[:i]]; !dup {
					kv[w[:i]] = w[i+1:]
				}
			}
		}
		src, dst := net.ParseIP(kv["src"]), net.ParseIP(kv["dst"])
		port, _ := strconv.Atoi(kv["dport"])
		if src == nil || dst == nil || port == 0 || !lan.Contains(src) || lan.Contains(dst) || dst.IsLoopback() || dst.IsMulticast() || dst.Equal(net.IPv4bcast) {
			continue
		}
		out[f[2]+"|"+kv["src"]+"|"+kv["sport"]+"|"+kv["dst"]+"|"+kv["dport"]] = ctFlow{f[2], kv["src"], kv["dst"], port}
	}
	return out
}

func portListed(rs []egressRule, proto string, port int) bool {
	for _, r := range rs {
		if r.Proto != proto {
			continue
		}
		for _, p := range strings.Split(r.Ports, ",") {
			if lo, hi, ok := strings.Cut(p, ":"); ok {
				a, _ := strconv.Atoi(lo)
				z, _ := strconv.Atoi(hi)
				if port >= a && port <= z {
					return true
				}
			} else if n, _ := strconv.Atoi(p); n == port {
				return true
			}
		}
	}
	return false
}

// Sample tallies the flows that the list would refuse (called every 10 s in monitor and enforce mode; in enforce mode a refused flow never reaches conntrack, so the tally is the monitor-time evidence).
func (m *egressMgr) Sample() {
	flows := parseConntrack(m.conn())
	arp := m.arp()
	ip2mac := map[string]string{}
	for mac, ip := range arp {
		ip2mac[ip] = mac
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().Unix()
	for k, fl := range flows {
		if _, dup := m.flows[k]; dup {
			m.flows[k] = now
			continue
		}
		m.flows[k] = now
		mac := ip2mac[fl.Src]
		if torBypassMgr != nil {
			torBypassMgr.ObserveFlow(mac, fl.Src, fl.Dst, time.Unix(now, 0))
		}
		if portListed(effectiveRules(m.cfg, mac), fl.Proto, fl.Port) {
			continue
		}
		key := mac + "|" + fl.Proto + "|" + strconv.Itoa(fl.Port)
		s := m.seen[key]
		if s == nil {
			if len(m.seen) >= 200 {
				continue
			}
			s = &egressSeen{MAC: mac, Proto: fl.Proto, Port: fl.Port}
			m.seen[key] = s
		}
		s.IP, s.Flows, s.Last = fl.Src, s.Flows+1, now
		if len(s.Dsts) < 3 && !contains(s.Dsts, fl.Dst) {
			s.Dsts = append(s.Dsts, fl.Dst)
		}
	}
	for k, t := range m.flows {
		if now-t > 600 {
			delete(m.flows, k)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (m *egressMgr) Run() {
	time.Sleep(20 * time.Second)
	for i := 0; ; i++ {
		if i%2 == 0 {
			m.Reconcile()
		}
		if m.Mode() != "off" {
			m.Sample()
		}
		time.Sleep(10 * time.Second)
	}
}

func (m *egressMgr) Mode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Mode
}

func (m *egressMgr) SetMode(mode string) error {
	if mode != "off" && mode != "monitor" && mode != "enforce" {
		return errors.New("mode must be off, monitor or enforce")
	}
	m.mu.Lock()
	m.cfg.Mode = mode
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.Reconcile()
	return nil
}

// Allow adds a rule (mac "" = every device), forgets the matching "would block" tallies; Remove deletes one.
func (m *egressMgr) Allow(r egressRule, mac string) error {
	if err := validRule(r); err != nil {
		return err
	}
	mac = strings.ToLower(mac)
	if mac != "" {
		if _, err := net.ParseMAC(mac); err != nil {
			return errors.New("bad MAC")
		}
	}
	m.mu.Lock()
	if mac == "" {
		m.cfg.Allow = append(m.cfg.Allow, r)
	} else {
		if m.cfg.Devices == nil {
			m.cfg.Devices = map[string][]egressRule{}
		}
		m.cfg.Devices[mac] = append(m.cfg.Devices[mac], r)
	}
	for k, s := range m.seen {
		if s.Proto == r.Proto && portListed([]egressRule{r}, s.Proto, s.Port) && (mac == "" || s.MAC == mac) {
			delete(m.seen, k)
		}
	}
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.Reconcile()
	return nil
}

func (m *egressMgr) Remove(r egressRule, mac string) error {
	mac = strings.ToLower(mac)
	m.mu.Lock()
	keep := func(rs []egressRule) []egressRule {
		var o []egressRule
		for _, x := range rs {
			if !(x.Proto == r.Proto && x.Ports == r.Ports) {
				o = append(o, x)
			}
		}
		return o
	}
	if mac == "" {
		m.cfg.Allow = keep(m.cfg.Allow)
	} else {
		m.cfg.Devices[mac] = keep(m.cfg.Devices[mac])
		if len(m.cfg.Devices[mac]) == 0 {
			delete(m.cfg.Devices, mac)
		}
	}
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.Reconcile()
	return nil
}

type egressSvcView struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Ports string `json:"ports"`
	On    bool   `json:"on"`              // ticked for everyone
	Extra bool   `json:"extra,omitempty"` // ticked for the asked device only
}

type egressView struct {
	Mode     string                  `json:"mode"`
	Services []egressSvcView         `json:"services"`
	Allow    []egressRule            `json:"allow"`
	Devices  map[string][]egressRule `json:"devices"`
	Observed []egressSeen            `json:"observed"`
	RulesIn  bool                    `json:"rules_in_place"`
	Error    string                  `json:"error,omitempty"`
}

// SetService ticks or unticks a service for everyone (mac "") or for one device.
func (m *egressMgr) SetService(id string, on bool, mac string) error {
	if _, ok := serviceByID(id); !ok {
		return errors.New("unknown service")
	}
	mac = strings.ToLower(mac)
	if mac != "" {
		if _, err := net.ParseMAC(mac); err != nil {
			return errors.New("bad MAC")
		}
	}
	set := func(l []string) []string {
		var out []string
		for _, x := range l {
			if x != id {
				out = append(out, x)
			}
		}
		if on {
			out = append(out, id)
		}
		return out
	}
	m.mu.Lock()
	if mac == "" {
		m.cfg.Services = set(m.cfg.Services)
	} else {
		if m.cfg.DevSvc == nil {
			m.cfg.DevSvc = map[string][]string{}
		}
		m.cfg.DevSvc[mac] = set(m.cfg.DevSvc[mac])
		if len(m.cfg.DevSvc[mac]) == 0 {
			delete(m.cfg.DevSvc, mac)
		}
	}
	for k, s := range m.seen { // what was refused for lack of this service is no longer news
		if sv, _ := serviceByID(id); on && portListed(sv.Rules, s.Proto, s.Port) && (mac == "" || s.MAC == mac) {
			delete(m.seen, k)
		}
	}
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.Reconcile()
	return nil
}

func (m *egressMgr) View() egressView { return m.ViewFor("") }

// ViewFor is the view with the "Extra" ticks for one device (mac "" = none).
func (m *egressMgr) ViewFor(mac string) egressView {
	m.mu.Lock()
	v := egressView{Mode: m.cfg.Mode, Allow: m.cfg.Allow, Devices: m.cfg.Devices, Error: m.lastErr}
	on := map[string]bool{}
	for _, id := range m.cfg.Services {
		on[id] = true
	}
	ex := map[string]bool{}
	for _, id := range m.cfg.DevSvc[strings.ToLower(mac)] {
		ex[id] = true
	}
	for _, sv := range egressServices {
		p := ""
		for _, r := range sv.Rules {
			p += r.Proto + " " + r.Ports + "; "
		}
		v.Services = append(v.Services, egressSvcView{ID: sv.ID, Name: sv.Name, Desc: sv.Desc, Ports: strings.TrimSuffix(p, "; "), On: on[sv.ID], Extra: ex[sv.ID]})
	}
	for _, s := range m.seen {
		v.Observed = append(v.Observed, *s)
	}
	m.mu.Unlock()
	sort.Slice(v.Observed, func(i, j int) bool { return v.Observed[i].Flows > v.Observed[j].Flows })
	// A nil slice or map marshals as null, and the page runs .map and .length on these: send real, empty lists so a unit with no rules yet still renders.
	if v.Allow == nil {
		v.Allow = []egressRule{}
	}
	if v.Devices == nil {
		v.Devices = map[string][]egressRule{}
	}
	if v.Observed == nil {
		v.Observed = []egressSeen{}
	}
	out, _ := run("iptables", "-S", "FORWARD")
	v.RulesIn = v.Mode == "off" || strings.Contains(out, "-j HS_EGRESS")
	return v
}
