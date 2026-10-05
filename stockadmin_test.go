package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newSA(t *testing.T) (*stockAdmin, *[]bool, *time.Time) {
	var calls []bool
	clock := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return &stockAdmin{flag: filepath.Join(t.TempDir(), "stockadmin.off"), now: func() time.Time { return clock }, apply: func(off bool) error { calls = append(calls, off); return nil }}, &calls, &clock
}

func TestStockAdminFlag(t *testing.T) {
	s, calls, clock := newSA(t)
	if s.Off() {
		t.Fatal("off by default")
	}
	if err := s.Set(true); err != nil || !s.Off() || len(*calls) != 1 || !(*calls)[0] {
		t.Fatalf("%v %v", err, *calls)
	}
	if _, err := os.Stat(s.flag); err != nil {
		t.Error("the flag file was not written")
	}
	// a restart (a new object, same file) must still see it off
	s2 := &stockAdmin{flag: s.flag, now: s.now, apply: s.apply}
	if !s2.Off() {
		t.Error("the setting did not survive a restart")
	}
	// removing the file by hand (the ssh undo) is noticed within a second
	os.Remove(s.flag)
	*clock = clock.Add(2 * time.Second)
	if s.Off() {
		t.Error("the manual undo was not noticed")
	}
	if err := s.Set(false); err != nil || len(*calls) != 2 || (*calls)[1] {
		t.Errorf("switching on twice must be harmless: %v %v", err, *calls)
	}
	var nilS *stockAdmin
	if nilS.Off() {
		t.Error("a nil manager must mean never off")
	}
}

func TestAdminScript(t *testing.T) {
	off := adminScript(true)
	for _, w := range []string{"iptables -N HS_ADMIN", "ip6tables -N HS_ADMIN", "--dports 81,444 ! -i lo -j REJECT --reject-with tcp-reset", "iptables -C INPUT -j HS_ADMIN", "ip6tables -I INPUT 1 -j HS_ADMIN"} {
		if !strings.Contains(off, w) {
			t.Errorf("off script lacks %q", w)
		}
	}
	on := adminScript(false)
	if strings.Contains(on, "-A HS_ADMIN") || !strings.Contains(on, "-D INPUT -j HS_ADMIN") || !strings.Contains(on, "ip6tables -F HS_ADMIN") {
		t.Errorf("on script:\n%s", on)
	}
	if strings.Contains(off, " 80,") || strings.Contains(off, ",80 ") || strings.Contains(off, ",443") {
		t.Error("the rules must not touch ports 80/443: those are our relay's")
	}
}

func TestRelayLANGoesToStockOrToUs(t *testing.T) {
	serve := func(msg string) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Write([]byte(msg))
				c.Close()
			}
		}()
		return l.Addr().String()
	}
	oldS, oldO, oldF := stockMap[443], ourMap[443], stockAdminOff
	defer func() { stockMap[443], ourMap[443], stockAdminOff = oldS, oldO, oldF }()
	stockMap[443], ourMap[443] = serve("STOCK"), serve("OURS")
	ask := func() string {
		a, b := net.Pipe()
		p := &porchRelay{}
		done := make(chan struct{})
		go func() { p.handleForTest(b, "192.168.1.1", "192.168.1.2"); close(done) }()
		a.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, _ := io.ReadAll(a)
		a.Close()
		<-done
		return string(got)
	}
	stockAdminOff = nil
	if got := ask(); got != "STOCK" {
		t.Errorf("no switch: %q", got)
	}
	stockAdminOff = func() bool { return false }
	if got := ask(); got != "STOCK" {
		t.Errorf("admin on: %q", got)
	}
	stockAdminOff = func() bool { return true }
	if got := ask(); got != "OURS" {
		t.Errorf("admin off, a LAN client must land on our page: %q", got)
	}
}
