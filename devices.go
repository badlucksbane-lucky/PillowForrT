package main

// The devices view: every device the box knows about, one row each, joining what the separate pages know: the radio (which band, how long connected), ARP and NDP
// (addresses, IPv4 and global IPv6), the DHCP reservations and the lease file (names, last lease), the block list, the firewall pauses and schedules. DNS activity and the VPN
// exit are joined by the page from /api/dns and /api/vpn. A device the radio does not list (wired, or asleep) still shows from its reservation or lease.

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

type devView struct {
	MAC          string   `json:"mac"`
	Label        string   `json:"label,omitempty"` // the name you gave it on the page
	Note         string   `json:"note,omitempty"`
	Name         string   `json:"name,omitempty"`     // the reservation name
	Hostname     string   `json:"hostname,omitempty"` // what the device told DHCP
	IP           string   `json:"ip,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	Online       bool     `json:"online"`
	Wifi         bool     `json:"wifi"`
	Band         string   `json:"band,omitempty"`
	ConnectedS   int      `json:"connected_s,omitempty"`
	Reserved     bool     `json:"reserved"`
	ReservedIP   string   `json:"reserved_ip,omitempty"`
	RandomMAC    bool     `json:"random_mac"` // a locally administered address: phones use these per network, so it can change
	Blocked      bool     `json:"blocked"`
	CutNow       bool     `json:"cut_now"` // internet cut right now by a pause or schedule
	PausedUntil  string   `json:"paused_until,omitempty"`
	Schedules    int      `json:"schedules"` // how many weekly windows name this device
	LeaseExpires int64    `json:"lease_expires,omitempty"`
	Since        int64    `json:"since,omitempty"`     // here since (unix), while online
	LastSeen     int64    `json:"last_seen,omitempty"` // the last time it was seen
	Vendor       string   `json:"vendor,omitempty"`    // what it announces in DHCP, e.g. android-dhcp-14
	Watched      bool     `json:"watched"`
}

type devInputs struct {
	ARP, Leases, NDP string
	Stations         []wifiStation
	Five             map[string]bool // MACs on the 5 GHz radio
	Reservations     []reservation
	Blocked          []string
	FW               fwView
	Notes            map[string]devNote
	Presence         map[string]presInfo
}

func isRandomMAC(mac string) bool {
	b, err := net.ParseMAC(mac)
	return err == nil && len(b) == 6 && b[0]&0x02 != 0
}

// buildDevices is a pure function over the inputs: unit-tested.
func buildDevices(in devInputs) []devView {
	byMAC := map[string]*devView{}
	get := func(mac string) *devView {
		mac = strings.ToLower(mac)
		if d, ok := byMAC[mac]; ok {
			return d
		}
		d := &devView{MAC: mac, RandomMAC: isRandomMAC(mac)}
		byMAC[mac] = d
		return d
	}
	for mac, ip := range parseARP(in.ARP) {
		d := get(mac)
		d.IP, d.Online = ip, true
	}
	for _, l := range strings.Split(in.Leases, "\n") { // expiry mac ip hostname clientid
		f := strings.Fields(l)
		if len(f) < 4 || strings.Count(f[1], ":") != 5 || net.ParseIP(f[2]) == nil {
			continue
		}
		d := get(f[1])
		if d.IP == "" {
			d.IP = f[2]
		}
		if f[3] != "*" {
			d.Hostname = f[3]
		}
		d.LeaseExpires, _ = strconv.ParseInt(f[0], 10, 64)
	}
	for ip, mac := range parseNDP(in.NDP) {
		if p := net.ParseIP(ip); p != nil && p.IsGlobalUnicast() && !p.IsPrivate() && p.To4() == nil {
			d := get(mac)
			d.IPv6 = append(d.IPv6, ip)
		}
	}
	for _, s := range in.Stations {
		d := get(s.MAC)
		d.Online, d.Wifi, d.ConnectedS = true, true, s.Connected
		d.Band = "2.4 GHz"
		if in.Five[s.MAC] {
			d.Band = "5 GHz"
		}
	}
	for _, r := range in.Reservations {
		d := get(r.MAC)
		d.Reserved, d.Name, d.ReservedIP = true, r.Name, r.IP
		if d.IP == "" {
			d.IP = r.IP
		}
	}
	for _, m := range in.Blocked {
		get(m).Blocked = true
	}
	cut := map[string]bool{}
	for _, m := range in.FW.CutNow {
		cut[m] = true
	}
	for _, p := range in.FW.Paused {
		d := get(p.MAC)
		d.PausedUntil = p.Until
	}
	for _, s := range in.FW.Sched {
		get(s.MAC).Schedules++
	}
	for mac, n := range in.Notes {
		if d, ok := byMAC[strings.ToLower(mac)]; ok {
			d.Label, d.Note = n.Label, n.Note
		} else if n.Label != "" || n.Note != "" {
			d := get(mac) // a labelled device that is not on the network now still shows, so it can be woken or edited
			d.Label, d.Note = n.Label, n.Note
		}
	}
	for mac, pi := range in.Presence {
		if d, ok := byMAC[strings.ToLower(mac)]; ok {
			d.LastSeen, d.Vendor, d.Watched = pi.LastSeen, pi.Vendor, pi.Watched
			if pi.Online {
				d.Since = pi.Since
			}
		}
	}
	var out []devView
	for mac, d := range byMAC {
		d.CutNow = cut[mac]
		sort.Strings(d.IPv6)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { // online first, then by address, then name
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		if a, b := ipNum(out[i].IP), ipNum(out[j].IP); a != b {
			return a < b
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

func readFile(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }

func gatherDevices() []devView {
	arp, _ := readFile("/proc/net/arp")
	leases, _ := readFile(*leasesFile)
	ndp, _ := run("ip", "-6", "neigh", "show", "dev", "bridge0")
	in := devInputs{ARP: arp, Leases: leases, NDP: ndp, Stations: parseStations(wifi.env.stations()), Five: map[string]bool{},
		Reservations: dhcpMgr.List(), Blocked: macMgr.List(), FW: fwMgr.View(nil), Notes: devMgr.All()}
	if presence != nil {
		in.Presence = presence.Info()
	}
	if wifi.env.stations5 != nil {
		for _, s := range parseStations(wifi.env.stations5()) {
			in.Five[s.MAC] = true
		}
	}
	return buildDevices(in)
}
