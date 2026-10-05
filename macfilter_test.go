package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mfRec struct {
	fw    [][]string
	kicks []string
	on    []string
}

func newMF(t *testing.T) (*macFilter, *mfRec) {
	r := &mfRec{}
	return &macFilter{listPath: filepath.Join(t.TempDir(), "list"),
		firewall: func(l []string) error { r.fw = append(r.fw, append([]string(nil), l...)); return nil },
		kick:     func(m string) error { r.kicks = append(r.kicks, m); return nil },
		online:   func() []string { return r.on }}, r
}

func TestMacFilterAddRemove(t *testing.T) {
	f, r := newMF(t)
	if err := f.Add("AA:BB:CC:DD:EE:01", "de:ad:be:ef:00:01"); err != nil {
		t.Fatal(err)
	}
	if l := f.List(); len(l) != 1 || l[0] != "aa:bb:cc:dd:ee:01" || len(r.fw) != 1 || len(r.kicks) != 1 {
		t.Fatalf("%v %+v", l, r)
	}
	for name, c := range map[string][2]string{"duplicate": {"aa:bb:cc:dd:ee:01", ""}, "self": {"de:ad:be:ef:00:01", "de:ad:be:ef:00:01"}, "bad": {"nonsense", ""}} {
		if f.Add(c[0], c[1]) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := f.Remove("aa:bb:cc:dd:ee:01"); err != nil || len(f.List()) != 0 || len(r.fw[len(r.fw)-1]) != 0 {
		t.Errorf("remove: %v %v", err, f.List())
	}
	if f.Remove("aa:bb:cc:dd:ee:01") == nil {
		t.Error("removing an unlisted MAC did not complain")
	}
	if fi, _ := os.Stat(f.listPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("list mode %v", fi.Mode())
	}
}

func TestMacFilterReconcileKicksAndReasserts(t *testing.T) {
	f, r := newMF(t)
	f.Add("aa:bb:cc:dd:ee:01", "")
	f.Add("aa:bb:cc:dd:ee:02", "")
	r.kicks, r.fw = nil, nil
	r.on = []string{"aa:bb:cc:dd:ee:02", "11:22:33:44:55:66"}
	f.Reconcile()
	if len(r.fw) != 1 || len(r.fw[0]) != 2 || len(r.kicks) != 1 || r.kicks[0] != "aa:bb:cc:dd:ee:02" {
		t.Errorf("%+v", r)
	}
}

func TestMacFilterFirewallFailureSaysSo(t *testing.T) {
	f, _ := newMF(t)
	f.firewall = func([]string) error { return errors.New("iptables is busy") }
	if err := f.Add("aa:bb:cc:dd:ee:01", ""); err == nil || !strings.Contains(err.Error(), "saved, but") {
		t.Errorf("%v", err)
	}
	if len(f.List()) != 1 {
		t.Error("list not saved")
	}
}

func TestMacFilterLimit(t *testing.T) {
	f, _ := newMF(t)
	for i := 0; i < 32; i++ {
		if err := f.Add("aa:bb:cc:dd:ee:"+hex2(i), ""); err != nil {
			t.Fatal(err)
		}
	}
	if f.Add("aa:bb:cc:dd:ff:00", "") == nil {
		t.Error("33rd accepted")
	}
}

func hex2(i int) string { const h = "0123456789abcdef"; return string([]byte{h[i>>4], h[i&15]}) }
