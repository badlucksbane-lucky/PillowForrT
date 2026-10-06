package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const torMAC = "aa:bb:cc:dd:ee:01"
const torMAC2 = "aa:bb:cc:dd:ee:02"

func TestTorrcIsClientOnly(t *testing.T) {
	rc := torrcFor("/var/volatile/tor", "/var/volatile/tor/notice.log")
	for _, want := range []string{"ClientOnly 1", "DNSPort 127.0.0.1:9053", "TransPort 192.168.1.1:9040", "SocksPort 192.168.1.1:9050", "SocksPolicy reject *", "DataDirectory /var/volatile/tor", "ClientUseIPv6 0", "SafeLogging 1"} {
		if !strings.Contains(rc, want+"\n") {
			t.Errorf("torrc is missing %q:\n%s", want, rc)
		}
	}
	for _, bad := range []string{"ORPort", "ExitRelay", "DirPort", "BridgeRelay", "ControlPort", "HiddenService", "ExitPolicy accept"} {
		if strings.Contains(rc, bad) {
			t.Errorf("a client-only torrc must not contain %q", bad)
		}
	}
	if strings.Contains(rc, "0.0.0.0") {
		t.Error("Tor must not listen on every interface (the cellular one included)")
	}
}

func TestTorRulesFailClosedPerDevice(t *testing.T) {
	nat, f, v6 := planTorRules(torRulePlan{Devices: []string{torMAC2, torMAC}, Onion: false})
	// TCP is redirected into Tor, except to the LAN and to DNS (which the stub answers through Tor)
	for _, want := range []string{
		"-A HS_TOR -m mac --mac-source " + torMAC + " -d 192.168.1.0/24 -j RETURN",
		"-A HS_TOR -m mac --mac-source " + torMAC + " -p udp --dport 53 -j RETURN",
		"-A HS_TOR -m mac --mac-source " + torMAC + " -p tcp --dport 53 -j RETURN",
		"-A HS_TOR -m mac --mac-source " + torMAC + " -p tcp -j REDIRECT --to-ports 9040",
		"-A HS_TOR -p tcp -d 198.18.0.0/16 -j REDIRECT --to-ports 9041",
	} {
		if !strings.Contains(nat, want+"\n") {
			t.Errorf("nat is missing %q:\n%s", want, nat)
		}
	}
	// everything else a Tor device forwards is DROPPED: UDP (QUIC, calls), ICMP, any non-TCP
	for _, m := range []string{torMAC, torMAC2} {
		if !strings.Contains(f, "-A HS_TORFW -m mac --mac-source "+m+" -j DROP\n") {
			t.Errorf("no catch-all DROP for %s:\n%s", m, f)
		}
		if !strings.Contains(v6, "-A HS_TOR6 -m mac --mac-source "+m+" -j REJECT") {
			t.Errorf("IPv6 is not refused for %s:\n%s", m, v6)
		}
	}
	// order: for each device the LAN exemption comes BEFORE the drop, and the redirect after the DNS exemption (first match wins)
	if strings.Index(f, "-d 192.168.1.0/24 -j RETURN") > strings.Index(f, "-j DROP") {
		t.Error("the LAN exemption must come before the DROP")
	}
	i := strings.Index(nat, "--dport 53 -j RETURN")
	j := strings.Index(nat, "-p tcp -j REDIRECT --to-ports 9040\n-A HS_TOR -m mac")
	if j >= 0 && i > j {
		t.Error("the DNS exemption must come before the catch-all redirect")
	}
	// nothing in the rules ever lets a Tor device's non-TCP traffic out: there is no ACCEPT in the forward chain
	if strings.Contains(f, "ACCEPT") || strings.Contains(nat, "ACCEPT") {
		t.Error("a Tor device's rules must never ACCEPT")
	}
	for _, blk := range []string{nat, f, v6} {
		if !strings.HasSuffix(blk, "COMMIT\n") {
			t.Error("every block is one atomic restore")
		}
	}
}

func TestTorRulesHouseWideOnionOnly(t *testing.T) {
	nat, f, v6 := planTorRules(torRulePlan{Onion: true})
	if !strings.Contains(nat, "-d 198.18.0.0/16 -j REDIRECT --to-ports 9041") {
		t.Error("house-wide .onion needs the virtual range redirected for everybody")
	}
	if strings.Contains(nat, "mac-source") || strings.Contains(f, "mac-source") || strings.Contains(v6, "mac-source") {
		t.Error("with no device assigned, no device is touched")
	}
	nat, _, _ = planTorRules(torRulePlan{})
	if strings.Contains(nat, "REDIRECT") {
		t.Error("with nothing on, nothing is redirected (the chain is emptied)")
	}
}

func TestParseBootstrap(t *testing.T) {
	log := "Oct 02 [notice] Bootstrapped 5% (conn): Connecting\nOct 02 [notice] Bootstrapped 45% (loading_status): x\nOct 02 [notice] Bootstrapped 100% (done): Done\n"
	if parseBootstrap(log) != 100 || parseBootstrap(log[:60]) != 5 || parseBootstrap("nothing") != -1 {
		t.Error("the last Bootstrapped line wins")
	}
}

func TestTorDecide(t *testing.T) {
	ok := uint64(60 * 1024)
	cases := []struct {
		o    torObs
		want string
	}{
		{torObs{Running: true, Want: true, AvailKB: ok, RSSKB: 30 * 1024}, ""},
		{torObs{Running: true, Want: true, AvailKB: 10 * 1024}, "yield"},
		{torObs{Running: true, Want: true, AvailKB: ok, RSSKB: 95 * 1024}, "yield"},
		{torObs{Running: true, Want: false, AvailKB: ok}, "stop"},
		{torObs{Running: true, Want: false, Yielding: true, AvailKB: ok}, ""},
		{torObs{Running: false, Want: true, AvailKB: ok}, "start"},
		{torObs{Running: false, Want: true, AvailKB: 30 * 1024}, ""},
		{torObs{Running: false, Want: false, AvailKB: ok}, ""},
	}
	for i, c := range cases {
		if got := torDecide(c.o); got != c.want {
			t.Errorf("case %d: %+v -> %q, want %q", i, c.o, got, c.want)
		}
	}
}

func testTor(t *testing.T) (*torMgr, *[]evt, *time.Time, *torRulePlan) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	var got []evt
	var applied torRulePlan
	m := &torMgr{path: filepath.Join(dir, "tor.json"), bin: filepath.Join(dir, "tor"), dataDir: filepath.Join(dir, "data"), torrc: filepath.Join(dir, "torrc"),
		logPath: filepath.Join(dir, "data", "notice.log"), boot: -1, wait: torMinRestartWait,
		now: func() time.Time { return now }, emit: func(e evt) { got = append(got, e) }}
	m.onions = newOnionMap()
	m.applyRules = func(p torRulePlan) error { applied = p; return nil }
	m.memAvail = func() uint64 { return 70 * 1024 }
	m.rssOf = func(int) uint64 { return 30 * 1024 }
	m.macOfIP = func() map[string]string { return map[string]string{"192.168.1.50": torMAC, "192.168.1.51": torMAC2} }
	m.nameOf = func(mac string) string { return map[string]string{torMAC: "phone"}[mac] }
	m.resolve = func(q []byte) ([]byte, error) { r := append([]byte(nil), q...); r[2] |= 0x80; return r, nil }
	return m, &got, &now, &applied
}

func TestTorDeviceAssignmentAndPersistence(t *testing.T) {
	m, _, _, applied := testTor(t)
	if err := m.SetDevice("nonsense", true); err == nil {
		t.Error("a bad MAC is refused")
	}
	if err := m.SetDevice(strings.ToUpper(torMAC), true); err != nil {
		t.Fatal(err)
	}
	if len(applied.Devices) != 1 || applied.Devices[0] != torMAC || !m.Active() {
		t.Errorf("the rules are applied at once: %+v", applied)
	}
	if err := m.Set(false, true); err != nil || !applied.Onion || len(applied.Devices) != 1 {
		t.Errorf("switching the daemon off must not release the device (fail closed): %+v %v", applied, err)
	}
	b, _ := os.ReadFile(m.path)
	if !strings.Contains(string(b), torMAC) {
		t.Errorf("saved: %s", b)
	}
	if err := m.SetDevice(torMAC, false); err != nil || len(applied.Devices) != 0 || m.Active() {
		t.Errorf("unassigning gives the direct line back: %+v", applied)
	}
	for i := 0; i < 16; i++ {
		m.SetDevice("aa:bb:cc:dd:01:"+string(rune('0'+i/10))+string(rune('0'+i%10)), true)
	}
	if m.SetDevice("aa:bb:cc:dd:02:00", true) == nil {
		t.Error("at most 16 devices")
	}
}

func TestTorSupervisor(t *testing.T) {
	m, got, now, _ := testTor(t)
	started := 0
	m.startProc = func(*torMgr) (*exec.Cmd, error) {
		started++
		c := exec.Command("sleep", "30")
		c.Start()
		return c, nil
	}
	defer func() {
		if m.cmd != nil {
			m.cmd.Process.Kill()
		}
	}()
	m.Tick()
	if started != 0 {
		t.Error("switched off: it does not start")
	}
	m.cfg.Enabled = true
	m.memAvail = func() uint64 { return 30 * 1024 }
	m.Tick()
	if started != 0 {
		t.Error("not enough free memory: it does not start")
	}
	m.memAvail = func() uint64 { return 70 * 1024 }
	m.Tick()
	if started != 1 || !m.running() {
		t.Fatal("it starts when enabled and memory allows")
	}
	if v := m.View(); !v.Running || v.Ready || v.Boot != 0 {
		t.Errorf("view while connecting: %+v", v)
	}
	os.MkdirAll(m.dataDir, 0o700)
	os.WriteFile(m.logPath, []byte("[notice] Bootstrapped 100% (done): Done\n"), 0o600)
	m.Tick()
	if !m.ready() || len(*got) != 1 || (*got)[0].Kind != "tor_ready" {
		t.Errorf("ready after 100%%: %v", *got)
	}
	// memory runs low: Tor yields, with an event, and does not come straight back
	m.memAvail = func() uint64 { return 15 * 1024 }
	m.Tick()
	if m.running() || m.yieldTil.IsZero() || (*got)[len(*got)-1].Kind != "tor_yield" || strings.Contains((*got)[len(*got)-1].Public, "MB") {
		t.Errorf("it yields on low memory with a generic public text: %v", *got)
	}
	m.memAvail = func() uint64 { return 70 * 1024 }
	m.Tick()
	if m.running() {
		t.Error("no restart during the yield pause")
	}
	*now = now.Add(11 * time.Minute)
	m.Tick()
	if !m.running() || started != 2 {
		t.Error("it comes back after the pause")
	}
	// a crash: restart with backoff and an event
	m.cmd.Process.Kill()
	m.cmd.Wait()
	m.Tick()
	if m.running() || m.restarts != 1 || (*got)[len(*got)-1].Kind != "tor_down" {
		t.Errorf("a crash is noticed: restarts %d %v", m.restarts, *got)
	}
	m.Tick()
	if m.running() {
		t.Error("backoff: not restarted at once")
	}
	*now = now.Add(torMinRestartWait + time.Second)
	m.Tick()
	if !m.running() {
		t.Error("restarted after the backoff")
	}
}

func TestTorDNSHook(t *testing.T) {
	m, _, _, _ := testTor(t)
	q := func(name string, typ uint16) ([]byte, dnsQuery) {
		b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, l := range strings.Split(name, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		b = append(b, 0, byte(typ>>8), byte(typ), 0, 1)
		dq, err := parseQuery(b)
		if err != nil {
			t.Fatal(err)
		}
		return b, dq
	}
	rc := func(r []byte) int { return int(r[3] & 0x0f) }
	// an ordinary device asking an ordinary name is none of our business
	b, dq := q("example.com", 1)
	if _, ok := m.DNS("192.168.1.60", dq, b); ok {
		t.Error("ordinary lookups are untouched")
	}
	// .onion with the house-wide switch off: NXDOMAIN, never upstream
	const goodOnion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	b, dq = q(goodOnion, 1)
	if r, ok := m.DNS("192.168.1.60", dq, b); !ok || rc(r) != 3 {
		t.Errorf(".onion off must be NXDOMAIN and handled: %v %v", r, ok)
	}
	// on but Tor not ready: SERVFAIL (fail closed)
	m.cfg.Onion = true
	if r, ok := m.DNS("192.168.1.60", dq, b); !ok || rc(r) != 2 {
		t.Errorf(".onion with Tor not ready must be SERVFAIL: %v %v", r, ok)
	}
	// ready: resolved through Tor, id preserved
	m.cmd = exec.Command("sleep", "30")
	m.cmd.Start()
	defer m.cmd.Process.Kill()
	m.boot = 100
	r, ok := m.DNS("192.168.1.60", dq, b)
	if !ok || len(r) < 16 || r[0] != 0x12 || r[1] != 0x34 || r[2]&0x80 == 0 || rc(r) != 0 || r[7] != 1 {
		t.Fatalf("a ready Tor gives .onion one answer: %v %v", r, ok)
	}
	if ip := net.IP(r[len(r)-4:]); ip[0] != 198 || ip[1] != 18 {
		t.Errorf("the answer is an address from the onion range: %v", ip)
	} else if n, ok := m.onions.nameFor(ip); !ok || n != goodOnion {
		t.Errorf("the address maps back to the name: %q %v", n, ok)
	}
	// AAAA for an onion name: no data (IPv6 is not carried); a made-up name: NXDOMAIN
	b6, dq6 := q(goodOnion, 28)
	if r, ok := m.DNS("192.168.1.60", dq6, b6); !ok || rc(r) != 0 || r[7] != 0 {
		t.Errorf("onion AAAA is NODATA: %v", r)
	}
	bb, dqb := q("abcdefghij.onion", 1)
	if r, ok := m.DNS("192.168.1.60", dqb, bb); !ok || rc(r) != 3 {
		t.Errorf("an invalid onion name is NXDOMAIN: %v", r)
	}
	// a Tor device: every name goes through Tor, even when it is not .onion; A/AAAA/PTR only, the rest is "no data"
	m.cfg.Devices = []string{torMAC}
	b, dq = q("example.com", 1)
	if r, ok := m.DNS("192.168.1.50", dq, b); !ok || r[2]&0x80 == 0 {
		t.Errorf("a Tor device resolves through Tor: %v %v", r, ok)
	}
	if _, ok := m.DNS("192.168.1.51", dq, b); ok {
		t.Error("a device not assigned to Tor is untouched")
	}
	b, dq = q("example.com", 28) // AAAA: IPv6 is not carried, so no answer rather than one that leads nowhere
	if r, ok := m.DNS("192.168.1.50", dq, b); !ok || rc(r) != 0 || r[7] != 0 {
		t.Errorf("AAAA for a Tor device is NODATA: %v %v", r, ok)
	}
	b, dq = q("example.com", 65) // HTTPS record
	if r, ok := m.DNS("192.168.1.50", dq, b); !ok || rc(r) != 0 || len(r) > len(b)+0 && r[7] != 0 {
		t.Errorf("types Tor cannot answer are NODATA, never forwarded: %v %v", r, ok)
	}
	// a Tor device while Tor is down: SERVFAIL, never a public resolver
	m.boot = -1
	b, dq = q("example.com", 1)
	if r, ok := m.DNS("192.168.1.50", dq, b); !ok || rc(r) != 2 {
		t.Errorf("fail closed: %v %v", r, ok)
	}
	// Tor's resolver failing is also SERVFAIL, not a fallback
	m.boot = 100
	m.resolve = func([]byte) ([]byte, error) { return nil, errors.New("down") }
	if r, ok := m.DNS("192.168.1.50", dq, b); !ok || rc(r) != 2 {
		t.Errorf("a failing Tor resolver is SERVFAIL: %v %v", r, ok)
	}
	var nilMgr *torMgr
	if _, ok := nilMgr.DNS("1.2.3.4", dq, b); ok {
		t.Error("a nil manager handles nothing")
	}
}

func TestTorViewBlockedAndStart(t *testing.T) {
	m, _, _, _ := testTor(t)
	m.cfg.Devices = []string{torMAC}
	v := m.View()
	if !v.Blocked || len(v.Devices) != 1 || v.Devices[0].Name != "phone" || !v.Devices[0].Online || v.Devices[0].IP != "192.168.1.50" || v.Installed {
		t.Errorf("assigned device with Tor not ready is shown as blocked: %+v", v)
	}
	os.MkdirAll(m.dataDir, 0o700)
	os.WriteFile(filepath.Join(m.dataDir, "state"), []byte("Guard x\n"), 0o600)
	os.WriteFile(filepath.Join(m.dataDir, "cached-microdescs.new"), []byte("big cache"), 0o600)
	os.WriteFile(filepath.Join(m.dataDir, "cached-microdesc-consensus"), []byte("consensus"), 0o600)
	os.WriteFile(m.bin, []byte("#!/bin/sh\nsleep 30\n"), 0o755)
	if os.Geteuid() == 0 { // startTorProc drops to "nobody", which must be able to reach the test's private temp dir
		for d := filepath.Dir(m.bin); d != os.TempDir() && d != "/"; d = filepath.Dir(d) {
			os.Chmod(d, 0o755)
		}
	}
	cmd, err := startTorProc(m)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill() }()
	if b, _ := os.ReadFile(m.torrc); !strings.Contains(string(b), "ClientOnly 1") {
		t.Error("torrc written")
	}
	for _, f := range []string{"cached-microdescs.new", "cached-microdesc-consensus"} {
		if _, err := os.Stat(filepath.Join(m.dataDir, f)); err == nil {
			t.Errorf("%s must be cleared before a start (a warm start peaks too high in memory)", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(m.dataDir, "state")); string(b) != "Guard x\n" {
		t.Errorf("the guard state must be kept: %q", b)
	}
}

func TestTorKillStrayOnlyKillsItsOwnBinary(t *testing.T) {
	m, _, _, _ := testTor(t)
	sl, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	data, _ := os.ReadFile(sl)
	os.WriteFile(m.bin, data, 0o755) // a real binary at the Tor path (a script would show up as its interpreter)
	stray := exec.Command(m.bin, "30")
	if err := stray.Start(); err != nil {
		t.Skip(err)
	}
	other := exec.Command("sleep", "30")
	other.Start()
	defer other.Process.Kill()
	defer stray.Process.Kill()
	time.Sleep(200 * time.Millisecond)
	m.killStray()
	done := make(chan error, 1)
	go func() { done <- stray.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("a stray Tor must be stopped")
	}
	if other.Process.Signal(syscall.Signal(0)) != nil {
		t.Error("an unrelated process must not be touched")
	}
}

func TestPlanTorCache(t *testing.T) {
	const mb = 1 << 20
	for _, c := range []struct {
		name          string
		main, journal int64
		want          torCachePlan
	}{
		{"nothing cached", 0, 0, torCacheWipe},
		{"a cold run's leftovers: only the journal (the 88 MB start)", 0, 37 * mb, torCacheWipe},
		{"seeded, nothing appended", 37 * mb, 0, torCacheKeep},
		{"seeded, a day of new descriptors", 37 * mb, 3 * mb, torCacheKeep},
		{"seeded, journal swollen past the cap", 37 * mb, 5 * mb, torCacheDropJournal},
		{"exactly at the cap", 37 * mb, torJournalCap, torCacheKeep},
		{"a journal at Tor's own rebuild point (half the main file)", 36 * mb, 18 * mb, torCacheDropJournal},
	} {
		if got := planTorCache(c.main, c.journal); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
	if torJournalCap >= 36*mb/2 {
		t.Error("the journal cap must stay well below the point where Tor rebuilds (half the main file)")
	}
}

func TestPrepareTorCacheFiles(t *testing.T) {
	put := func(dir, name string, n int) {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	has := func(dir, name string) bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil }

	d := t.TempDir() // seeded and healthy: everything public stays, stale-format files go
	for _, f := range []string{"cached-microdescs", "cached-microdesc-consensus", "cached-certs", "state", "unverified-microdesc-consensus", "cached-consensus"} {
		put(d, f, 100)
	}
	put(d, "cached-microdescs.new", 1000)
	prepareTorCache(d)
	for _, f := range []string{"cached-microdescs", "cached-microdescs.new", "cached-microdesc-consensus", "cached-certs", "state"} {
		if !has(d, f) {
			t.Errorf("seeded cache: %s was removed", f)
		}
	}
	for _, f := range []string{"unverified-microdesc-consensus", "cached-consensus"} {
		if has(d, f) {
			t.Errorf("seeded cache: stale %s was kept", f)
		}
	}

	d = t.TempDir() // a cold run's leftovers: the journal alone, with its consensus: wiped, but the guard state and certs stay
	put(d, "cached-microdescs.new", torJournalCap+1)
	for _, f := range []string{"cached-microdesc-consensus", "cached-certs", "state"} {
		put(d, f, 100)
	}
	prepareTorCache(d)
	if has(d, "cached-microdescs.new") || has(d, "cached-microdesc-consensus") {
		t.Error("a journal with no main file must be wiped with its consensus")
	}
	if !has(d, "state") || !has(d, "cached-certs") {
		t.Error("the guard state and the authority certificates must survive a wipe")
	}

	d = t.TempDir() // swollen journal behind a main file: only the journal goes
	put(d, "cached-microdescs", 100)
	put(d, "cached-microdescs.new", torJournalCap+1)
	put(d, "cached-microdesc-consensus", 100)
	prepareTorCache(d)
	if has(d, "cached-microdescs.new") || !has(d, "cached-microdescs") || !has(d, "cached-microdesc-consensus") {
		t.Error("a swollen journal must go alone")
	}
}
