package main

// DHCP reservations (MAC -> fixed address + name), moved here from the stock admin. They live in /data/dhcp_hosts, one `MAC,IP,name` per line, which dnsmasq reads with
// --dhcp-hostsfile; a SIGHUP makes it re-read the file (tested). Every change is validated, the old file is backed up, and the new one is written atomically.

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const dhcpHeader = "# DHCP reservations (MAC,IP,name), managed from https://orbic/ . dnsmasq re-reads this file on SIGHUP. Edit here only if the web page is unavailable.\n"

var (
	macRe  = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
)

type reservation struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

func parseReservations(text string) []reservation {
	var out []reservation
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		p := strings.Split(l, ",")
		if len(p) < 2 {
			continue
		}
		r := reservation{MAC: strings.ToLower(strings.TrimSpace(p[0])), IP: strings.TrimSpace(p[1])}
		if len(p) > 2 {
			r.Name = strings.TrimSpace(p[2])
		}
		if macRe.MatchString(r.MAC) && net.ParseIP(r.IP) != nil {
			out = append(out, r)
		}
	}
	return out
}

func formatReservations(rs []reservation) string {
	sorted := append([]reservation(nil), rs...)
	sort.Slice(sorted, func(i, j int) bool { return ipNum(sorted[i].IP) < ipNum(sorted[j].IP) })
	var b strings.Builder
	b.WriteString(dhcpHeader)
	for _, r := range sorted {
		fmt.Fprintf(&b, "%s,%s,%s\n", r.MAC, r.IP, r.Name)
	}
	return b.String()
}

func ipNum(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// the LAN is 192.168.1.0/24: .1 (the gateway) and .254 (the services address) are ours, clients use .2 to .252 (.253 is the canary)
func validateReservation(r reservation, others []reservation) error {
	if !macRe.MatchString(r.MAC) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	ip := net.ParseIP(r.IP).To4()
	if ip == nil || ip[0] != 192 || ip[1] != 168 || ip[2] != 1 || ip[3] < 2 || ip[3] > 252 {
		return errors.New("the address must be 192.168.1.2 to 192.168.1.252 (.1 and .254 belong to the Orbic, .253 is the canary)")
	}
	if !nameRe.MatchString(r.Name) {
		return errors.New("the name must be 1 to 32 letters, digits, - or _ (starting with a letter or digit)")
	}
	for _, o := range others {
		if o.MAC == r.MAC {
			continue
		}
		if o.IP == r.IP {
			return fmt.Errorf("%s is already reserved for %s", r.IP, o.Name)
		}
		if strings.EqualFold(o.Name, r.Name) {
			return fmt.Errorf("the name %s is already used", r.Name)
		}
	}
	return nil
}

type dhcpManager struct {
	mu        sync.Mutex
	path      string
	backupDir string
	reload    func() error               // SIGHUP dnsmasq
	release   func(ip, mac string) error // make dnsmasq forget a device's lease (DHCPRELEASE)
	curIP     func(mac string) string    // the address a MAC holds now
	leaseIP   func(mac string) string    // the address the lease file says a MAC holds (even if the device is gone)
}

func defaultDHCPManager() *dhcpManager {
	return &dhcpManager{path: *dhcpHostsFile, backupDir: filepath.Join(*secureDir, "backups"),
		release: func(ip, mac string) error { return sendRelease("bridge0", ip, mac) }, curIP: currentAddress, leaseIP: func(mac string) string { return (&dhcpManager{}).leaseOf(mac) }, reload: func() error {
			out, err := run("sh", "-c", "kill -HUP $(cat /data/dnsmasq.pid)")
			if err != nil {
				return fmt.Errorf("could not tell dnsmasq to reload: %v %s", err, out)
			}
			return nil
		}}
}

func (d *dhcpManager) List() []reservation {
	b, _ := os.ReadFile(d.path)
	return parseReservations(string(b))
}

func (d *dhcpManager) save(rs []reservation) error {
	old, _ := os.ReadFile(d.path)
	if len(old) > 0 {
		os.MkdirAll(d.backupDir, 0o700)
		os.WriteFile(filepath.Join(d.backupDir, "dhcp_hosts-"+time.Now().Format("20060102-150405")), old, 0o600)
		if es, _ := os.ReadDir(d.backupDir); len(es) > 40 { // the directory also holds Wi-Fi backups: trim only ours, oldest first
			var ours []string
			for _, e := range es {
				if strings.HasPrefix(e.Name(), "dhcp_hosts-") {
					ours = append(ours, e.Name())
				}
			}
			sort.Strings(ours)
			for len(ours) > 8 {
				os.Remove(filepath.Join(d.backupDir, ours[0]))
				ours = ours[1:]
			}
		}
	}
	if err := writeFileAtomic(d.path, []byte(formatReservations(rs)), 0o644); err != nil {
		return err
	}
	if err := d.reload(); err != nil {
		// the file is saved; dnsmasq will read it at its next start: say so rather than pretend
		return fmt.Errorf("saved, but %v", err)
	}
	return nil
}

// Set adds a reservation or changes the one for that MAC.
func (d *dhcpManager) Set(r reservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r.MAC = strings.ToLower(strings.TrimSpace(r.MAC))
	r.IP, r.Name = strings.TrimSpace(r.IP), strings.TrimSpace(r.Name)
	rs := d.List()
	if err := validateReservation(r, rs); err != nil {
		return err
	}
	found := false
	for i := range rs {
		if rs[i].MAC == r.MAC {
			rs[i], found = r, true
		}
	}
	if !found {
		if len(rs) >= 64 {
			return errors.New("too many reservations (64 is the limit here)")
		}
		rs = append(rs, r)
	}
	if err := d.save(rs); err != nil {
		return err
	}
	d.dropStaleLease(r) // a device that holds another address would otherwise just renew it
	return nil
}

// dropStaleLease releases the lease a device holds at an address other than its reservation, so the reservation is used the next time it asks.
func (d *dhcpManager) dropStaleLease(r reservation) {
	if d.curIP == nil || d.release == nil {
		return
	}
	if cur := d.curIP(r.MAC); cur != "" && cur != r.IP {
		d.release(cur, r.MAC)
	}
}

// leaseOf reads the lease file (expiry MAC IP name clientid) for the address a MAC holds there, even if the device is gone.
func (d *dhcpManager) leaseOf(mac string) string {
	b, err := os.ReadFile(*leasesFile)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && strings.EqualFold(f[1], mac) && net.ParseIP(f[2]) != nil {
			return f[2]
		}
	}
	return ""
}

// Forget makes dnsmasq drop whatever lease this MAC holds (a device that changed MAC leaves its old lease holding the address its reservation moved to).
func (d *dhcpManager) Forget(mac string) (string, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return "", errors.New("not a MAC address")
	}
	ip := ""
	if d.leaseIP != nil {
		ip = d.leaseIP(mac)
	}
	if ip == "" {
		return "", errors.New("dnsmasq has no lease for that MAC address")
	}
	if err := d.release(ip, mac); err != nil {
		return "", err
	}
	return ip, nil
}

// MoveNow tells dnsmasq to forget the device's current lease (it is told to reconnect by the caller). It returns the address that was released.
func (d *dhcpManager) MoveNow(mac string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	var res *reservation
	for _, r := range d.List() {
		if r.MAC == mac {
			r := r
			res = &r
		}
	}
	if res == nil {
		return "", errors.New("that device has no reservation")
	}
	cur := ""
	if d.curIP != nil {
		cur = d.curIP(mac)
	}
	if cur == "" {
		return "", errors.New("that device is not on the network right now")
	}
	if cur == res.IP {
		return "", errors.New("it already has its reserved address")
	}
	if err := d.release(cur, mac); err != nil {
		return "", err
	}
	return cur, nil
}

func (d *dhcpManager) Delete(mac string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	rs := d.List()
	var keep []reservation
	for _, r := range rs {
		if r.MAC != mac {
			keep = append(keep, r)
		}
	}
	if len(keep) == len(rs) {
		return errors.New("no reservation for that MAC address")
	}
	if err := d.save(keep); err != nil {
		return err
	}
	if d.leaseIP != nil && d.release != nil { // the address goes back to the pool at once
		if ip := d.leaseIP(mac); ip != "" {
			d.release(ip, mac)
		}
	}
	return nil
}

// device is anything seen on the LAN right now, for the "add from a connected device" picker.
type lanDevice struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Name     string `json:"name,omitempty"`
	Reserved bool   `json:"reserved"`
	Wifi     bool   `json:"wifi"`
}

type dhcpView struct {
	Reservations []reservationView `json:"reservations"`
	Devices      []lanDevice       `json:"devices"`
	Range        string            `json:"range,omitempty"`
}
type reservationView struct {
	reservation
	Online bool   `json:"online"`
	SeenAs string `json:"seen_as,omitempty"` // the address the device really holds now, when it differs from its reservation
}

func (d *dhcpManager) View(arp, leases string, stations []wifiStation, dnsmasqCmd string) dhcpView {
	byIP := macMapFromARP(arp, leases) // ip -> mac (ARP first, leases for the sleepers)
	macToIP := map[string]string{}
	for ip, mac := range byIP {
		macToIP[mac] = ip
	}
	live := map[string]bool{}
	for mac := range parseARP(arp) {
		live[mac] = true
	}
	wifi := map[string]bool{}
	for _, s := range stations {
		wifi[s.MAC] = true
		live[s.MAC] = true
	}
	rs := d.List()
	resMAC := map[string]reservation{}
	for _, r := range rs {
		resMAC[r.MAC] = r
	}
	v := dhcpView{Range: dhcpRange(dnsmasqCmd)}
	sort.Slice(rs, func(i, j int) bool { return ipNum(rs[i].IP) < ipNum(rs[j].IP) })
	for _, r := range rs {
		rv := reservationView{reservation: r, Online: live[r.MAC]}
		if ip := macToIP[r.MAC]; live[r.MAC] && ip != "" && ip != r.IP {
			rv.SeenAs = ip
		}
		v.Reservations = append(v.Reservations, rv)
	}
	seen := map[string]bool{}
	add := func(mac, ip string) {
		if mac == "" || seen[mac] {
			return
		}
		seen[mac] = true
		_, res := resMAC[mac]
		v.Devices = append(v.Devices, lanDevice{MAC: mac, IP: ip, Name: resMAC[mac].Name, Reserved: res, Wifi: wifi[mac]})
	}
	for mac, ip := range macToIP {
		if live[mac] {
			add(mac, ip)
		}
	}
	for _, s := range stations {
		add(s.MAC, macToIP[s.MAC])
	}
	sort.Slice(v.Devices, func(i, j int) bool { return ipNum(v.Devices[i].IP) < ipNum(v.Devices[j].IP) })
	return v
}

// dhcpRange pulls the dynamic pool out of dnsmasq's own command line (e.g. 192.168.1.100 to 192.168.1.200, 1 day).
func dhcpRange(cmd string) string {
	for _, a := range strings.Fields(cmd) {
		if v, ok := strings.CutPrefix(a, "--dhcp-range=bridge0,"); ok {
			p := strings.Split(v, ",")
			if len(p) >= 4 {
				secs := 0
				fmt.Sscanf(p[3], "%d", &secs)
				return fmt.Sprintf("%s to %s, leases %s", p[0], p[1], leaseText(secs))
			}
		}
	}
	return ""
}

func leaseText(s int) string {
	switch {
	case s >= 86400 && s%86400 == 0:
		return fmt.Sprintf("%d day(s)", s/86400)
	case s >= 3600:
		return fmt.Sprintf("%d hour(s)", s/3600)
	}
	return fmt.Sprintf("%d s", s)
}

// ReplaceAll swaps the whole reservation list (a restore). The list must already be validated.
func (d *dhcpManager) ReplaceAll(rs []reservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.save(rs)
}
