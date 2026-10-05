package main

// The DHCP pool (first address, last address, lease time), moved here from the stock admin. The stock firmware keeps it in
// /usrdata/data/qcmap/mobileap_cfg.xml (<DHCPCfg>), and its qcmap daemon turns that into dnsmasq's --dhcp-range at boot. Changing the pool therefore means
// (1) editing that file, so it survives a reboot, and (2) relaunching dnsmasq with the new --dhcp-range now, with the same command line otherwise. If dnsmasq
// does not come back healthy, the old file and the old command line are put back.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dhcpPool struct {
	Start     string `json:"start"`
	End       string `json:"end"`
	LeaseSecs int    `json:"lease_secs"`
}

type poolView struct {
	dhcpPool
	Running  *dhcpPool `json:"running,omitempty"` // what dnsmasq is using right now, shown only when it differs from the saved settings
	Reserved []string  `json:"reserved_inside,omitempty"`
}

const (
	minLease = 120
	maxLease = 7 * 86400
)

var (
	startRe = regexp.MustCompile(`(<StartIP>)[^<]*(</StartIP>)`)
	endRe   = regexp.MustCompile(`(<EndIP>)[^<]*(</EndIP>)`)
	leaseRe = regexp.MustCompile(`(<LeaseTime>)[^<]*(</LeaseTime>)`)
)

// readPoolXML pulls the pool out of the stock config text.
func readPoolXML(text string) (dhcpPool, error) {
	get := func(tag string) string {
		m := regexp.MustCompile(`<` + tag + `>([^<]*)</` + tag + `>`).FindStringSubmatch(text)
		if m == nil {
			return ""
		}
		return strings.TrimSpace(m[1])
	}
	p := dhcpPool{Start: get("StartIP"), End: get("EndIP")}
	n, err := strconv.Atoi(get("LeaseTime"))
	if p.Start == "" || p.End == "" || err != nil {
		return p, errors.New("the stock config has no DHCP pool section")
	}
	p.LeaseSecs = n
	return p, nil
}

func validatePool(p dhcpPool) error {
	lo, hi := net.ParseIP(p.Start).To4(), net.ParseIP(p.End).To4()
	for _, ip := range []net.IP{lo, hi} {
		if ip == nil || ip[0] != 192 || ip[1] != 168 || ip[2] != 1 || ip[3] < 2 || ip[3] > 252 {
			return errors.New("the pool must lie inside 192.168.1.2 to 192.168.1.252 (.1 and .254 belong to the Orbic, .253 is the canary)")
		}
	}
	if ipNum(p.Start) > ipNum(p.End) {
		return errors.New("the first address must not be after the last one")
	}
	if ipNum(p.End)-ipNum(p.Start)+1 < 8 {
		return errors.New("the pool needs at least 8 addresses")
	}
	if p.LeaseSecs < minLease || p.LeaseSecs > maxLease {
		return fmt.Errorf("the lease time must be between %d seconds and 7 days", minLease)
	}
	return nil
}

// rangeArg is dnsmasq's own form of the pool.
func rangeArg(p dhcpPool) string {
	return fmt.Sprintf("--dhcp-range=bridge0,%s,%s,255.255.255.0,%d", p.Start, p.End, p.LeaseSecs)
}

// poolFromArgs finds the IPv4 pool in a dnsmasq command line (the IPv6 `--dhcp-range=::,::` is left alone).
func poolFromArgs(args []string) (dhcpPool, bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--dhcp-range=bridge0,"); ok {
			f := strings.Split(v, ",")
			if len(f) >= 4 {
				n, _ := strconv.Atoi(f[3])
				return dhcpPool{Start: f[0], End: f[1], LeaseSecs: n}, true
			}
		}
	}
	return dhcpPool{}, false
}

func replacePoolArg(args []string, p dhcpPool) ([]string, bool) {
	out := append([]string(nil), args...)
	for i, a := range out {
		if strings.HasPrefix(a, "--dhcp-range=bridge0,") {
			out[i] = rangeArg(p)
			return out, true
		}
	}
	return out, false
}

type poolManager struct {
	mu        sync.Mutex
	cfgPath   string
	backupDir string
	args      func() ([]string, error)      // dnsmasq's running command line
	relaunch  func(old, new []string) error // stop dnsmasq, start it with `new`, and check it is healthy; error if not
	reserved  func() []reservation
}

func defaultPoolManager(d *dhcpManager) *poolManager {
	return &poolManager{cfgPath: *qcmapCfgFile, backupDir: filepath.Join(*secureDir, "backups"), reserved: d.List,
		args: func() ([]string, error) {
			pid, err := os.ReadFile("/data/dnsmasq.pid")
			if err != nil {
				return nil, err
			}
			b, err := os.ReadFile("/proc/" + strings.TrimSpace(string(pid)) + "/cmdline")
			if err != nil {
				return nil, err
			}
			return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), nil
		},
		relaunch: relaunchDnsmasq}
}

// relaunchDnsmasq replaces the running dnsmasq (the way dnsmasq-swap.sh does) and checks that DHCP and DNS answer; the caller restores on error.
func relaunchDnsmasq(old, new []string) error {
	if len(new) == 0 {
		return errors.New("no command line to start")
	}
	run("sh", "-c", "kill $(pidof dnsmasq) 2>/dev/null; sleep 2; kill -9 $(pidof dnsmasq) 2>/dev/null; sleep 1")
	if out, err := run(new[0], new[1:]...); err != nil {
		return fmt.Errorf("dnsmasq did not start: %v %s", err, out)
	}
	time.Sleep(3 * time.Second)
	if out, err := run("sh", "-c", "pidof dnsmasq >/dev/null && nslookup example.com 127.0.0.1 2>/dev/null | grep -q 'Address.*[0-9]'"); err != nil {
		return fmt.Errorf("dnsmasq is not answering: %v %s", err, out)
	}
	return nil
}

func (m *poolManager) View() (poolView, error) {
	b, err := os.ReadFile(m.cfgPath)
	if err != nil {
		return poolView{}, err
	}
	p, err := readPoolXML(string(b))
	if err != nil {
		return poolView{}, err
	}
	v := poolView{dhcpPool: p}
	if args, err := m.args(); err == nil {
		if rp, ok := poolFromArgs(args); ok && rp != p {
			v.Running = &rp
		}
	}
	if m.reserved != nil {
		for _, r := range m.reserved() {
			if n := ipNum(r.IP); n >= ipNum(p.Start) && n <= ipNum(p.End) {
				v.Reserved = append(v.Reserved, r.Name+" "+r.IP)
			}
		}
		sort.Strings(v.Reserved)
	}
	return v, nil
}

// Set saves the pool and applies it to the running dnsmasq. DNS blinks for a few seconds while dnsmasq restarts.
func (m *poolManager) Set(p dhcpPool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validatePool(p); err != nil {
		return "", err
	}
	old, err := os.ReadFile(m.cfgPath)
	if err != nil {
		return "", err
	}
	cur, err := readPoolXML(string(old))
	if err != nil {
		return "", err
	}
	oldArgs, err := m.args()
	if err != nil {
		return "", fmt.Errorf("cannot read dnsmasq's command line: %v", err)
	}
	newArgs, ok := replacePoolArg(oldArgs, p)
	if !ok {
		return "", errors.New("dnsmasq is not running with an IPv4 pool, so nothing was changed")
	}
	if rp, _ := poolFromArgs(oldArgs); rp == p && cur == p {
		return "", errors.New("nothing to change")
	}
	os.MkdirAll(m.backupDir, 0o700)
	if err := os.WriteFile(filepath.Join(m.backupDir, "mobileap_cfg-"+time.Now().Format("20060102-150405")+".xml"), old, 0o600); err != nil {
		return "", fmt.Errorf("could not back up the stock config: %v", err)
	}
	trimBackups(m.backupDir, "mobileap_cfg-", 8)
	text := startRe.ReplaceAllString(string(old), "${1}"+p.Start+"${2}")
	text = endRe.ReplaceAllString(text, "${1}"+p.End+"${2}")
	text = leaseRe.ReplaceAllString(text, "${1}"+strconv.Itoa(p.LeaseSecs)+"${2}")
	if err := writeFileAtomic(m.cfgPath, []byte(text), 0o755); err != nil {
		return "", err
	}
	if err := m.relaunch(oldArgs, newArgs); err != nil {
		writeFileAtomic(m.cfgPath, old, 0o755)
		if e2 := m.relaunch(newArgs, oldArgs); e2 != nil {
			return "", fmt.Errorf("%v; and putting the old pool back failed too: %v (dnsmasq-swap.sh restarts it within a minute)", err, e2)
		}
		return "", fmt.Errorf("dnsmasq would not take the new pool (%v): the old pool is back", err)
	}
	return fmt.Sprintf("saved: %s to %s, leases %s. Devices keep their current address until they renew; an address outside the pool is kept until its lease ends.", p.Start, p.End, leaseText(p.LeaseSecs)), nil
}

func trimBackups(dir, prefix string, keep int) {
	es, _ := os.ReadDir(dir)
	var ours []string
	for _, e := range es {
		if strings.HasPrefix(e.Name(), prefix) {
			ours = append(ours, e.Name())
		}
	}
	sort.Strings(ours)
	for len(ours) > keep {
		os.Remove(filepath.Join(dir, ours[0]))
		ours = ours[1:]
	}
}
