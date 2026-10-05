package main

// Tor on the Orbic: a minimal client-only Tor (recipe orbic-tor) supervised by tinyfwd, used two ways.
//
//   House-wide .onion: any device can open a .onion name with no setup. The DNS stub answers an A query for a valid v3 .onion name with an address from 198.18.0.0/16 and a firewall rule
//   sends TCP aimed at that range to the onion bridge (onionbridge.go), which connects to the name through Tor's SOCKS port. (Tor's own DNS port cannot give an onion name an IPv4 address, hence the
//   bridge. Browsers that read proxy.pac also get a SOCKS rule for .onion.) A .onion name never goes to a public resolver: with the switch off it gets NXDOMAIN, with Tor not ready SERVFAIL.
//
//   Per device: a device chosen on the page has ALL its internet traffic forced through Tor, enforced in the kernel by MAC address, and FAILS CLOSED:
//     nat    HS_TOR   : its TCP (except to the LAN and DNS) is REDIRECTed into Tor's transparent port; with Tor down that is a refused connection, never a direct one
//     filter HS_TORFW : whatever else it tries to forward (UDP including QUIC, ICMP, anything not TCP) is DROPPED. Tor carries only TCP, so these would otherwise leave directly
//                           from the cellular address, which is the classic leak.
//     ip6    HS_TOR6  : its IPv6 is refused (IPv6 would bypass Tor); apps fall back to IPv4
//     DNS    its lookups still reach the DNS stub (blocklists apply), which answers them through Tor's DNS port, or SERVFAIL when Tor is not ready: never from a public resolver.
//   The device assignment is separate from the daemon switch ON PURPOSE: switching Tor off leaves an assigned device blocked, not suddenly direct; unassign it to give it back its direct line.
//   A Tor device is not also sent through Mullvad (the Tor rules come first). Tor's own connections leave the Orbic by the cellular link.
//
// Memory is the hard limit (one core, ~77 MB available, no swap): the supervisor lowers Tor's priority, watches its resident size and the box's free memory, and stops Tor first (a "yield",
// with an event) rather than let the kernel pick a modem daemon, and Tor carries oom_score_adj 1000 so that if it comes to the kernel's choice, Tor is the one. The data directory is on FLASH
// (/data/proxy/tor-data): it holds a 37 MB descriptor cache that Tor rewrites in place, which as a RAM disk needed up to double that and starved the whole router (2026-10-02); on flash it is written
// rarely (AvoidDiskWrites) and its pages are reclaimable cache.

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	torTransPort = 9040
	torDNSPort   = 9053
	torSocksPort = 9050
	torVirtCIDR  = "198.18.0.0/16" // the private addresses the DNS stub gives .onion names (onionbridge.go)
	torHouseIP   = "192.168.1.1"
)

type torConfig struct {
	Enabled bool      `json:"enabled"` // the daemon runs
	Onion   bool      `json:"onion"`   // house-wide .onion
	Devices []string  `json:"devices"` // MACs whose traffic is forced through Tor
	Door    onionDoor `json:"door"`    // the onion door (onion.go): remote web (read-only) and SSH for a few keyed devices
}

// ---- pure pieces: torrc, firewall rules, log parsing, the supervisor's decisions ----

// torrcFor renders the configuration. Client only: no ORPort, no exit, no directory service.
func torrcFor(dataDir, logPath string, extra ...string) string {
	lines := []string{
		"DataDirectory " + dataDir,
		"Log notice file " + logPath,
		"ClientOnly 1",
		"AvoidDiskWrites 1",
		"SocksPort 127.0.0.1:" + strconv.Itoa(torSocksPort),
		"SocksPort " + torHouseIP + ":" + strconv.Itoa(torSocksPort),
		"SocksPolicy accept 127.0.0.1",
		"SocksPolicy accept " + lanCIDR,
		"SocksPolicy reject *",
		"DNSPort 127.0.0.1:" + strconv.Itoa(torDNSPort),
		"TransPort " + torHouseIP + ":" + strconv.Itoa(torTransPort),
		"ClientUseIPv6 0",
		"MaxMemInQueues 20 MB",
		"ConnLimit 200",
		"DisableDebuggerAttachment 1",
		"SafeLogging 1",
	}
	return strings.Join(append(lines, append(extra, "")...), "\n")
}

type torRulePlan struct {
	Devices []string
	Onion   bool
}

func (p torRulePlan) active() bool { return len(p.Devices) > 0 }

// planTorRules renders the three iptables-restore blocks. Pure and unit-tested; every chain is rewritten in one atomic commit.
func planTorRules(p torRulePlan) (nat, filter, v6 string) {
	var n, f, s strings.Builder
	n.WriteString("*nat\n:HS_TOR - [0:0]\n")
	f.WriteString("*filter\n:HS_TORFW - [0:0]\n")
	s.WriteString("*filter\n:HS_TOR6 - [0:0]\n")
	devs := append([]string(nil), p.Devices...)
	sort.Strings(devs)
	if p.Onion || p.active() {
		fmt.Fprintf(&n, "-A HS_TOR -p tcp -d %s -j REDIRECT --to-ports %d\n", torVirtCIDR, torBridgePort)
	}
	for _, m := range devs {
		mr := macRule(m)
		fmt.Fprintf(&n, "-A HS_TOR %s -d %s -j RETURN\n", mr, lanCIDR)
		fmt.Fprintf(&n, "-A HS_TOR %s -p udp --dport 53 -j RETURN\n", mr)
		fmt.Fprintf(&n, "-A HS_TOR %s -p tcp --dport 53 -j RETURN\n", mr)
		fmt.Fprintf(&n, "-A HS_TOR %s -p tcp -j REDIRECT --to-ports %d\n", mr, torTransPort)
		fmt.Fprintf(&f, "-A HS_TORFW %s -d %s -j RETURN\n", mr, lanCIDR)
		fmt.Fprintf(&f, "-A HS_TORFW %s -j DROP\n", mr)
		fmt.Fprintf(&s, "-A HS_TOR6 %s -j REJECT --reject-with icmp6-port-unreachable\n", mr)
	}
	n.WriteString("COMMIT\n")
	f.WriteString("COMMIT\n")
	s.WriteString("COMMIT\n")
	return n.String(), f.String(), s.String()
}

var torBootRe = regexp.MustCompile(`Bootstrapped (\d+)%`)

// parseBootstrap returns the last bootstrap percentage in a chunk of the notice log (-1 if none).
func parseBootstrap(log string) int {
	m := torBootRe.FindAllStringSubmatch(log, -1)
	if len(m) == 0 {
		return -1
	}
	n, _ := strconv.Atoi(m[len(m)-1][1])
	return n
}

type torObs struct {
	Running   bool
	RSSKB     uint64
	AvailKB   uint64
	Want      bool // enabled and not yielding
	Yielding  bool
	YieldDone bool // the yield pause is over
}

const (
	torRSSLimitKB     = 90 * 1024
	torYieldBelowKB   = 20 * 1024 // stop Tor when the box has less than this available
	torResumeAboveKB  = 60 * 1024 // and only start it again with at least this much
	torYieldPause     = 10 * time.Minute
	torMinRestartWait = 15 * time.Second
	torMaxRestartWait = 5 * time.Minute
)

// torDecide is the supervisor's rule, as a pure function: what to do now. Returns "start", "stop", "yield" or "".
func torDecide(o torObs) string {
	switch {
	case o.Running && o.RSSKB > torRSSLimitKB:
		return "yield"
	case o.Running && o.AvailKB > 0 && o.AvailKB < torYieldBelowKB:
		return "yield"
	case o.Running && !o.Want && !o.Yielding:
		return "stop"
	case !o.Running && o.Want && o.AvailKB >= torResumeAboveKB:
		return "start"
	}
	return ""
}

// ---- the manager ----

type torMgr struct {
	mu        sync.Mutex
	path      string // settings
	bin       string
	dataDir   string
	torrc     string
	logPath   string
	stateBak  string // the guard state, kept on flash
	cfg       torConfig
	cmd       *exec.Cmd
	startedAt time.Time
	boot      int
	restarts  int
	lastErr   string
	yieldTil  time.Time
	wait      time.Duration
	nextTry   time.Time
	ipSet     map[string]bool
	ipAt      time.Time
	now       func() time.Time
	emit      func(evt)
	// replaceable for tests
	applyRules func(torRulePlan) error
	memAvail   func() uint64
	rssOf      func(pid int) uint64
	macOfIP    func() map[string]string
	nameOf     func(mac string) string
	startProc  func(m *torMgr) (*exec.Cmd, error)
	resolve    func(q []byte) ([]byte, error)
	onions     *onionMap
}

func newTorMgr() *torMgr {
	m := &torMgr{path: *torFile, bin: *torBin, dataDir: "/data/proxy/tor-data", torrc: "/var/volatile/torrc", logPath: "/var/volatile/tor-notice.log",
		now: time.Now, boot: -1, wait: torMinRestartWait,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		}}
	m.applyRules = applyTorRules
	m.memAvail = func() uint64 { return memAvailKB() }
	m.rssOf = func(pid int) uint64 {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
		if err != nil {
			return 0
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "VmRSS:") {
				f := strings.Fields(l)
				if len(f) >= 2 {
					v, _ := strconv.ParseUint(f[1], 10, 64)
					return v
				}
			}
		}
		return 0
	}
	m.macOfIP = func() map[string]string {
		arp, _ := os.ReadFile("/proc/net/arp")
		lease, _ := os.ReadFile(*leasesFile)
		return macMapFromARP(string(arp), string(lease))
	}
	m.nameOf = func(mac string) string {
		names, _ := lanNames()
		return names[mac]
	}
	m.startProc = startTorProc
	m.resolve = torResolve
	m.onions = newOnionMap()
	if b, err := os.ReadFile(m.path); err == nil {
		json.Unmarshal(b, &m.cfg)
	}
	return m
}

func (m *torMgr) save() {
	b, _ := json.Marshal(m.cfg)
	writeFileAtomic(m.path, b, 0o600)
}

func (m *torMgr) plan() torRulePlan {
	return torRulePlan{Devices: append([]string(nil), m.cfg.Devices...), Onion: m.cfg.Onion}
}

// Active says whether any device is forced through Tor (the Qualcomm fast path must then stay unloaded, as for Mullvad).
func (m *torMgr) Active() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cfg.Devices) > 0
}

func (m *torMgr) running() bool {
	return m.cmd != nil && m.cmd.Process != nil && m.cmd.ProcessState == nil
}

// The directory cache and what to do with it before a start (measured on the companion computer 2026-10-03, TOR.md "Where Tor's memory goes").
// Tor keeps microdescriptors in cached-microdescs (the main file, which it maps read-only: about 11 MB of real memory plus file pages the kernel can
// drop) and appends new ones to cached-microdescs.new (the journal). A start that finds ONLY a big journal parses it all into the heap and rebuilds
// the main file: 44 MB kept and an 88 MB peak (the router fell to 12 MB free on 2026-10-02). Tor rebuilds at load when the journal is over 16 KB and
// either larger than half the main file or the dropped bytes exceed a third (microdesc.c, should_rebuild_md_cache); a journal under torJournalCap
// never gets there. So the rebuilt main file is kept (a companion computer makes it), a swollen journal is dropped (Tor fetches those few
// descriptors again), and a journal with no main file behind it is wiped: that is the cold start, the only safe one without a seed.
const torJournalCap = 4 << 20

type torCachePlan int

const (
	torCacheKeep        torCachePlan = iota // main file and consensus stay
	torCacheDropJournal                     // the main file stays, the journal goes
	torCacheWipe                            // everything cached goes (a cold start)
)

// planTorCache decides from the sizes of cached-microdescs (main) and cached-microdescs.new (journal); negative or zero means absent.
func planTorCache(mainSize, journalSize int64) torCachePlan {
	if mainSize <= 0 {
		return torCacheWipe
	}
	if journalSize > torJournalCap {
		return torCacheDropJournal
	}
	return torCacheKeep
}

// prepareTorCache applies the plan. Only `state` (the guard relays), `keys` and the public authority certificates are ever kept besides the main file and consensus.
func prepareTorCache(dir string) {
	size := func(name string) int64 {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return fi.Size()
		}
		return 0
	}
	rm := func(names ...string) {
		for _, f := range names {
			os.Remove(filepath.Join(dir, f))
		}
	}
	rm("unverified-microdesc-consensus", "cached-consensus", "cached-descriptors", "cached-descriptors.new", "cached-extrainfo", "cached-extrainfo.new")
	switch planTorCache(size("cached-microdescs"), size("cached-microdescs.new")) {
	case torCacheWipe:
		rm("cached-microdescs", "cached-microdescs.new", "cached-microdesc-consensus")
	case torCacheDropJournal:
		rm("cached-microdescs.new")
	}
}

func startTorProc(m *torMgr) (*exec.Cmd, error) {
	if _, err := os.Stat(m.bin); err != nil {
		return nil, fmt.Errorf("the Tor binary is not installed (%s)", m.bin)
	}
	if err := os.MkdirAll(m.dataDir, 0o700); err != nil {
		return nil, err
	}
	os.Remove(m.logPath)
	prepareTorCache(m.dataDir)
	if err := syncOnionDir(m.onionDir(), m.cfg.Door, torOwner()); err != nil { // the caller (Tick) holds m.mu
		return nil, err
	}
	if err := os.WriteFile(m.torrc, []byte(m.renderTorrc()), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command(m.bin, "-f", m.torrc)
	cmd.Env = append(os.Environ(), "MALLOC_ARENA_MAX=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if os.Geteuid() == 0 { // never run Tor as root: the unprivileged "nobody" ids (numeric, the Orbic has no name lookups for a static program); it needs nothing privileged
		const nobody = 65534
		os.Chmod(m.torrc, 0o644)
		filepath.WalkDir(m.dataDir, func(p string, _ os.DirEntry, err error) error { // files from an earlier run as root (or by another user) must be readable
			if err == nil {
				os.Lchown(p, nobody, nobody)
			}
			return nil
		})
		// the kernel is Android-derived (paranoid network): creating any socket needs the "inet" group, 3003
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: nobody, Gid: nobody, Groups: []uint32{3003}}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, 10) // yield the one core to the proxy and the radio
	// if memory ever runs out the kernel must choose Tor, never a modem daemon or tinyfwd (found 2026-10-02: a squeeze starved tinyfwd too, so its own watchdog could not act in time)
	os.WriteFile("/proc/"+strconv.Itoa(cmd.Process.Pid)+"/oom_score_adj", []byte("1000"), 0o644)
	go cmd.Wait()
	return cmd, nil
}

func (m *torMgr) stopProc() {
	if m.cmd == nil || m.cmd.Process == nil {
		return
	}
	syscall.Kill(-m.cmd.Process.Pid, syscall.SIGTERM)
	for i := 0; i < 30 && m.cmd.ProcessState == nil; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if m.cmd.ProcessState == nil {
		syscall.Kill(-m.cmd.Process.Pid, syscall.SIGKILL)
	}
	m.cmd, m.boot = nil, -1
}

func (m *torMgr) readBoot() {
	f, err := os.Open(m.logPath)
	if err != nil {
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.Size() > 256*1024 { // a quiet client logs little; never let the RAM-disk log grow without bound
		f.Close()
		os.Truncate(m.logPath, 0)
		return
	}
	off := st.Size() - 8192
	if off < 0 {
		off = 0
	}
	f.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(bufio.NewReader(f))
	if p := parseBootstrap(string(b)); p >= 0 {
		m.boot = p
	}
}

// Tick is one supervisor step (called every 10 seconds).
func (m *torMgr) Tick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	yielding := now.Before(m.yieldTil)
	run := m.running()
	if m.cmd != nil && !run { // it exited by itself
		m.cmd, m.boot = nil, -1
		m.restarts++
		m.lastErr = "Tor exited unexpectedly"
		m.nextTry = now.Add(m.wait)
		if m.wait *= 2; m.wait > torMaxRestartWait {
			m.wait = torMaxRestartWait
		}
		m.emit(evt{T: now.Unix(), Kind: "tor_down", Sev: sevAttention, Text: "Tor stopped unexpectedly and will be restarted. Devices sent through Tor stay blocked, not direct, until it is back.", Public: "The Tor service stopped and is restarting"})
	}
	o := torObs{Running: run, AvailKB: m.memAvail(), Want: m.cfg.Enabled && !yielding && !now.Before(m.nextTry), Yielding: yielding}
	if run {
		o.RSSKB = m.rssOf(m.cmd.Process.Pid)
	}
	switch torDecide(o) {
	case "yield":
		m.stopProc()
		m.yieldTil = now.Add(torYieldPause)
		m.lastErr = fmt.Sprintf("stopped to protect the router's memory (%d MB available, Tor was using %d MB)", o.AvailKB/1024, o.RSSKB/1024)
		m.emit(evt{T: now.Unix(), Kind: "tor_yield", Sev: sevAttention, Text: "Tor was stopped because the Orbic was running low on memory (" + m.lastErr + "). It starts again in about 10 minutes if memory allows.", Public: "The Tor service paused to protect the router's memory"})
	case "stop":
		m.stopProc()
		m.lastErr = ""
	case "start":
		cmd, err := m.startProc(m)
		if err != nil {
			m.lastErr = err.Error()
			m.nextTry = now.Add(m.wait)
			return
		}
		m.cmd, m.startedAt, m.boot, m.lastErr = cmd, now, 0, ""
	}
	if m.running() {
		was := m.boot
		m.readBoot()
		if was < 100 && m.boot == 100 {
			m.wait = torMinRestartWait // a good start resets the backoff
			m.emit(evt{T: now.Unix(), Kind: "tor_ready", Sev: sevInfo, Text: "Tor is connected and ready.", Public: "The Tor service is ready"})
		}
	}
}

// Reconcile applies the firewall plan. Always applied, whether or not the daemon runs: an assigned device stays blocked (fail closed) while Tor is off.
func (m *torMgr) Reconcile() error {
	m.mu.Lock()
	p := m.plan()
	m.mu.Unlock()
	return m.applyRules(p)
}

// torSFEOff records that Tor devices are why the fast path is unloaded (see manageSFE): it is loaded back only when no Tor device is left and the VPN does not need it off either.
var torSFEOff atomic.Bool

func applyTorRules(p torRulePlan) error {
	switch {
	case p.active() && !torSFEOff.Load():
		manageSFE(true)
		torSFEOff.Store(true)
	case !p.active() && torSFEOff.Load():
		torSFEOff.Store(false)
		if vpn != nil {
			vpn.Reconcile() // the VPN decides whether the fast path stays off
		} else {
			manageSFE(false)
		}
	}
	ensureTorHooks()
	nat, f, s := planTorRules(p)
	for _, r := range []struct{ cmd, rules string }{{"iptables-restore", nat}, {"iptables-restore", f}, {"ip6tables-restore", s}} {
		if err := restore(r.cmd, r.rules); err != nil {
			return err
		}
	}
	return nil
}

// ensureTorHooks makes sure the chains are called first (the stock firmware can rebuild its tables).
func ensureTorHooks() {
	type h struct{ cmd, table, chain, spec, target string }
	for _, x := range []h{
		{"iptables", "nat", "PREROUTING", "-i bridge0 -j HS_TOR", "HS_TOR"},
		{"iptables", "filter", "FORWARD", "-j HS_TORFW", "HS_TORFW"},
		{"ip6tables", "filter", "FORWARD", "-j HS_TOR6", "HS_TOR6"},
	} {
		// the chain must exist before it can be hooked (iptables-restore declares it, but the first hook can come before the first restore)
		run("sh", "-c", fmt.Sprintf("%s -t %s -N %s 2>/dev/null", x.cmd, x.table, x.target))
		if _, err := run("sh", "-c", fmt.Sprintf("%s -t %s -C %s %s 2>/dev/null || %s -t %s -I %s 1 %s", x.cmd, x.table, x.chain, x.spec, x.cmd, x.table, x.chain, x.spec)); err != nil {
			fmt.Fprintf(os.Stderr, "tor: hook %s %s: %v\n", x.cmd, x.chain, err)
		}
	}
}

// killStray stops a Tor left running by a previous tinyfwd (a restart of the daemon, a deploy): it runs in its own process group so it outlives its parent, and a second one would
// fail on the data directory lock. Its data directory (in RAM) survives, so the new one starts from the cached directory information in seconds.
func (m *torMgr) killStray() {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && strings.HasPrefix(string(b), m.bin+"\x00") {
			syscall.Kill(pid, syscall.SIGTERM)
		}
	}
}

func (m *torMgr) Run() {
	m.killStray()
	m.mu.Lock()
	if err := m.applyDoorLocked(); err != nil { // after a boot: the authorized_clients files and the SSH flag match the settings again
		m.lastErr = "onion door: " + err.Error()
	}
	m.mu.Unlock()
	time.Sleep(40 * time.Second) // after a boot: let the uplink, DNS and the clock settle (Tor needs a sane clock)
	n := 0
	for {
		m.Tick()
		m.mu.Lock()
		fast := m.running() && m.boot < 100 // while Tor connects its memory grows fast: look every 2 seconds
		m.mu.Unlock()
		if fast {
			time.Sleep(2 * time.Second)
		} else {
			time.Sleep(10 * time.Second)
		}
		if n++; n%8 == 1 { // rules about every 20 seconds: cheap, and repairs a table the firmware rebuilt
			if err := m.Reconcile(); err != nil {
				m.mu.Lock()
				m.lastErr = "firewall: " + err.Error()
				m.mu.Unlock()
			}
		}
	}
}

// ---- who is a Tor device, and the DNS hook ----

func (m *torMgr) refreshIPs() {
	if m.macOfIP == nil {
		return
	}
	want := map[string]bool{}
	for _, d := range m.cfg.Devices {
		want[d] = true
	}
	set := map[string]bool{}
	for ip, mac := range m.macOfIP() {
		if want[mac] {
			set[ip] = true
		}
	}
	m.ipSet, m.ipAt = set, m.now()
}

// IsDevice says whether a client address belongs to a device forced through Tor.
func (m *torMgr) IsDevice(ip string) bool {
	if m == nil || ip == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cfg.Devices) == 0 {
		return false
	}
	if m.ipSet == nil || m.now().Sub(m.ipAt) > 5*time.Second {
		m.refreshIPs()
	}
	return m.ipSet[ip]
}

func (m *torMgr) ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running() && m.boot >= 100
}

// DNS answers a query that must not reach a public resolver: a .onion name (anyone), or any name asked by a Tor device. handled is false for everything else.
func (m *torMgr) DNS(client string, dq dnsQuery, q []byte) (resp []byte, handled bool) {
	if m == nil {
		return nil, false
	}
	onion := dq.Name == "onion" || strings.HasSuffix(dq.Name, ".onion")
	dev := m.IsDevice(client)
	if !onion && !dev {
		return nil, false
	}
	m.mu.Lock()
	house := m.cfg.Onion
	m.mu.Unlock()
	if onion && !house && !dev {
		return buildRcode(q, dq, 3), true // house-wide .onion is off: NXDOMAIN, and never upstream
	}
	if onion {
		switch {
		case !validOnion(dq.Name):
			return buildRcode(q, dq, 3), true // not a v3 onion name: it cannot exist
		case !m.ready():
			return buildRcode(q, dq, 2), true // Tor is not ready: SERVFAIL, fail closed
		case dq.Type == 1:
			return buildA(q, dq, m.onions.ipFor(dq.Name), 30), true // an address from the onion range; the onion bridge finishes the job (onionbridge.go)
		default:
			return buildRcode(q, dq, 0), true // AAAA and the rest: no data (IPv6 is not carried)
		}
	}
	if dq.Type != 1 && dq.Type != 12 { // A and PTR only: IPv6 is not carried (an AAAA answer would only send a client down a path that is refused), and Tor's DNS port speaks nothing else; the rest is "no data", never a leak
		return buildRcode(q, dq, 0), true
	}
	if !m.ready() {
		return buildRcode(q, dq, 2), true // SERVFAIL: fail closed
	}
	r, err := m.resolve(q)
	if err != nil || len(r) < 12 {
		return buildRcode(q, dq, 2), true
	}
	setID(r, dq.ID)
	return r, true
}

func torResolve(q []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", "127.0.0.1:"+strconv.Itoa(torDNSPort), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second)) // the first lookup of a name may need a new circuit
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ---- settings ----

func (m *torMgr) Set(enabled, onion bool) error {
	m.mu.Lock()
	m.cfg.Enabled, m.cfg.Onion = enabled, onion
	if enabled {
		m.yieldTil, m.nextTry, m.wait = time.Time{}, time.Time{}, torMinRestartWait
	}
	m.save()
	m.mu.Unlock()
	return m.Reconcile()
}

func (m *torMgr) SetDevice(mac string, on bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	m.mu.Lock()
	var keep []string
	for _, d := range m.cfg.Devices {
		if d != mac {
			keep = append(keep, d)
		}
	}
	if on {
		if len(keep) >= 16 {
			m.mu.Unlock()
			return errors.New("too many devices (16 is the limit)")
		}
		if selfMAC := ownBridgeMAC(); mac == selfMAC {
			m.mu.Unlock()
			return errors.New("that is the Orbic's own address")
		}
		keep = append(keep, mac)
	}
	m.cfg.Devices = keep
	m.ipSet = nil
	m.save()
	m.mu.Unlock()
	return m.Reconcile()
}

func ownBridgeMAC() string {
	if ifc, err := net.InterfaceByName("bridge0"); err == nil {
		return macStr(ifc.HardwareAddr)
	}
	return ""
}

// ---- the page ----

type torDeviceView struct {
	MAC    string `json:"mac"`
	Name   string `json:"name,omitempty"`
	IP     string `json:"ip,omitempty"`
	Online bool   `json:"online"`
}

type torView struct {
	Available bool            `json:"available"`
	Installed bool            `json:"installed"`
	Enabled   bool            `json:"enabled"`
	Onion     bool            `json:"onion"`
	Running   bool            `json:"running"`
	Ready     bool            `json:"ready"`
	Boot      int             `json:"bootstrap"` // percent; -1 not running
	UpS       int64           `json:"up_s,omitempty"`
	RSSMB     float64         `json:"rss_mb,omitempty"`
	AvailMB   float64         `json:"avail_mb"`
	Restarts  int             `json:"restarts"`
	Yielding  bool            `json:"yielding"`
	YieldLeft int64           `json:"yield_left_s,omitempty"`
	Err       string          `json:"error,omitempty"`
	Socks     string          `json:"socks"`
	Devices   []torDeviceView `json:"devices"`
	Blocked   bool            `json:"blocked"` // assigned devices exist but Tor is not ready: they have no internet (by design)
}

func (m *torMgr) View() torView {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ierr := os.Stat(m.bin)
	v := torView{Available: true, Installed: ierr == nil, Enabled: m.cfg.Enabled, Onion: m.cfg.Onion, Running: m.running(), Boot: m.boot, Restarts: m.restarts, Err: m.lastErr,
		Socks: torHouseIP + ":" + strconv.Itoa(torSocksPort), AvailMB: float64(m.memAvail()) / 1024, Devices: []torDeviceView{}}
	if v.Running {
		v.Ready = m.boot >= 100
		v.UpS = int64(m.now().Sub(m.startedAt).Seconds())
		v.RSSMB = float64(m.rssOf(m.cmd.Process.Pid)) / 1024
	} else {
		v.Boot = -1
	}
	if left := m.yieldTil.Sub(m.now()); left > 0 {
		v.Yielding, v.YieldLeft = true, int64(left.Seconds())
	}
	ips := map[string]string{}
	if m.macOfIP != nil {
		for ip, mac := range m.macOfIP() {
			ips[mac] = ip
		}
	}
	for _, d := range m.cfg.Devices {
		dv := torDeviceView{MAC: d, IP: ips[d], Online: ips[d] != ""}
		if m.nameOf != nil {
			dv.Name = m.nameOf(d)
		}
		v.Devices = append(v.Devices, dv)
	}
	v.Blocked = len(v.Devices) > 0 && !v.Ready
	return v
}

// torSelfTest asks check.torproject.org, through the local SOCKS port, whether the request arrived from Tor. It proves Tor works on the Orbic; a device's own path needs a test from the device.
func torSelfTest() (map[string]any, error) {
	host := "check.torproject.org"
	c, err := socksConnect(onionSocksAddr, host, 443, 60*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: host, RootCAs: rootPool(), MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	if _, err := tc.Write([]byte("GET /api/ip HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: tinyfwd\r\nConnection: close\r\n\r\n")); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(tc, 16384))
	if err != nil && len(raw) == 0 {
		return nil, err
	}
	i := strings.Index(string(raw), "\r\n\r\n")
	if i < 0 {
		return nil, errors.New("no answer body")
	}
	var out map[string]any
	if err := json.Unmarshal(raw[i+4:], &out); err != nil {
		return nil, err
	}
	return out, nil
}

var torMgrG *torMgr
