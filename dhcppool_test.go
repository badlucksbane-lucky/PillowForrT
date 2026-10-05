package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const poolXML = "<config><DHCPCfg>\n<StartIP>192.168.1.100</StartIP>\n<EndIP>192.168.1.200</EndIP>\n<LeaseTime>86400</LeaseTime>\n</DHCPCfg><Other>keep</Other></config>"

var poolArgs = []string{"/data/proxy/dnsmasq", "-n", "--dhcp-range=bridge0,192.168.1.100,192.168.1.200,255.255.255.0,86400", "--dhcp-range=::,::", "--dhcp-option=option6:dns-server,[fe80::1]"}

func newPoolMgr(t *testing.T, relaunch func(o, n []string) error) (*poolManager, string, *[][]string) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "mobileap_cfg.xml")
	os.WriteFile(cfg, []byte(poolXML), 0o755)
	var launched [][]string
	m := &poolManager{cfgPath: cfg, backupDir: filepath.Join(dir, "bk"), args: func() ([]string, error) { return poolArgs, nil },
		relaunch: func(o, n []string) error { launched = append(launched, n); return relaunch(o, n) }}
	return m, cfg, &launched
}

func TestPoolValidate(t *testing.T) {
	ok := dhcpPool{"192.168.1.50", "192.168.1.150", 3600}
	if err := validatePool(ok); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]dhcpPool{
		"gateway":   {"192.168.1.1", "192.168.1.150", 3600},
		"services":  {"192.168.1.50", "192.168.1.254", 3600},
		"othernet":  {"10.0.0.5", "10.0.0.50", 3600},
		"backwards": {"192.168.1.150", "192.168.1.50", 3600},
		"tiny":      {"192.168.1.50", "192.168.1.54", 3600},
		"short":     {"192.168.1.50", "192.168.1.150", 30},
		"long":      {"192.168.1.50", "192.168.1.150", 8 * 86400},
		"junk":      {"x", "y", 3600},
	} {
		if validatePool(p) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPoolSetAppliesAndKeepsTheRest(t *testing.T) {
	m, cfg, launched := newPoolMgr(t, func(o, n []string) error { return nil })
	msg, err := m.Set(dhcpPool{"192.168.1.50", "192.168.1.150", 7200})
	if err != nil || !strings.Contains(msg, "192.168.1.50") {
		t.Fatalf("%v %q", err, msg)
	}
	b, _ := os.ReadFile(cfg)
	p, _ := readPoolXML(string(b))
	if p != (dhcpPool{"192.168.1.50", "192.168.1.150", 7200}) || !strings.Contains(string(b), "<Other>keep</Other>") {
		t.Errorf("config %s", b)
	}
	n := (*launched)[0]
	if n[2] != "--dhcp-range=bridge0,192.168.1.50,192.168.1.150,255.255.255.0,7200" || n[3] != "--dhcp-range=::,::" || n[4] != poolArgs[4] || len(n) != len(poolArgs) {
		t.Errorf("new command line %v", n)
	}
	if poolArgs[2] != "--dhcp-range=bridge0,192.168.1.100,192.168.1.200,255.255.255.0,86400" {
		t.Error("the running command line was modified in place")
	}
	if es, _ := os.ReadDir(m.backupDir); len(es) != 1 {
		t.Error("no backup")
	}
}

func TestPoolRollbackWhenDnsmasqFails(t *testing.T) {
	calls := 0
	m, cfg, launched := newPoolMgr(t, func(o, n []string) error {
		calls++
		if calls == 1 {
			return errors.New("dnsmasq is not answering")
		}
		return nil
	})
	if _, err := m.Set(dhcpPool{"192.168.1.50", "192.168.1.150", 7200}); err == nil || !strings.Contains(err.Error(), "old pool is back") {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != poolXML {
		t.Errorf("config not restored: %s", b)
	}
	if len(*launched) != 2 || (*launched)[1][2] != poolArgs[2] {
		t.Errorf("old command line not relaunched: %v", *launched)
	}
}

func TestPoolNoChangeAndBadInput(t *testing.T) {
	m, cfg, launched := newPoolMgr(t, func(o, n []string) error { return nil })
	if _, err := m.Set(dhcpPool{"192.168.1.100", "192.168.1.200", 86400}); err == nil {
		t.Error("an identical pool was applied")
	}
	if _, err := m.Set(dhcpPool{"192.168.1.1", "192.168.1.200", 86400}); err == nil {
		t.Error("bad pool accepted")
	}
	if b, _ := os.ReadFile(cfg); string(b) != poolXML || len(*launched) != 0 {
		t.Error("something changed")
	}
}

func TestPoolViewShowsMismatchAndReservations(t *testing.T) {
	m, cfg, _ := newPoolMgr(t, nil)
	m.reserved = func() []reservation {
		return []reservation{{"a", "192.168.1.150", "inside"}, {"b", "192.168.1.10", "outside"}}
	}
	v, err := m.View()
	if err != nil || v.Running != nil || len(v.Reserved) != 1 || v.Reserved[0] != "inside 192.168.1.150" {
		t.Fatalf("%v %+v", err, v)
	}
	os.WriteFile(cfg, []byte(strings.Replace(poolXML, "86400", "3600", 1)), 0o755)
	if v, _ = m.View(); v.Running == nil || v.Running.LeaseSecs != 86400 {
		t.Errorf("mismatch not shown: %+v", v)
	}
}
