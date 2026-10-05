package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWithdrawRA(t *testing.T) {
	mac, _ := net.ParseMAC("00:00:5e:00:53:0b")
	pre := net.ParseIP("2600:100a:b057:b54d::")
	p := buildWithdrawRA(mac, pre)
	if len(p) != 56 || p[0] != 134 || p[6] != 0 || p[7] != 0 { // type, router lifetime (bytes 6-7) zero
		t.Fatalf("bad header: len %d % x", len(p), p[:8])
	}
	if !bytes.Equal(p[16:24], []byte{1, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x0b}) {
		t.Errorf("source link-layer option wrong: % x", p[16:24])
	}
	o := p[24:]
	if o[0] != 3 || o[1] != 4 || o[2] != 64 || o[3] != 0xC0 || !bytes.Equal(o[4:12], make([]byte, 8)) {
		t.Errorf("prefix option must be len 64, L|A, valid 0, preferred 0: % x", o[:12])
	}
	if !bytes.Equal(o[16:], pre.To16()) {
		t.Errorf("prefix wrong: % x", o[16:])
	}
}

func TestLanV6Script(t *testing.T) {
	on, off := lanV6Script(false), lanV6Script(true)
	for _, w := range []string{"--icmpv6-type 134 -j DROP", "--mark 0x4e -j RETURN", "-I OUTPUT 1 -j HS_LANV6_RA", "-I FORWARD 1 -j HS_LANV6_FWD", "-o rmnet_data+ -j REJECT"} {
		if !strings.Contains(off, w) {
			t.Errorf("off script lacks %q", w)
		}
	}
	if strings.Contains(on, "DROP") || strings.Contains(on, "-I OUTPUT") || !strings.Contains(on, "-D OUTPUT -j HS_LANV6_RA") {
		t.Errorf("on script must unhook and flush, not add rules:\n%s", on)
	}
}

func TestLanV6SetAndFlag(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "lanv6.on")
	var applied []bool
	sent := 0
	s := &lanV6{flag: flag, now: time.Now, apply: func(o bool) error { applied = append(applied, o); return nil }, withdraw: func() error { sent++; return nil }}
	if !s.Off() {
		t.Fatal("must be OFF when there is no flag file (the default)")
	}
	if err := s.Set(false); err != nil { // switch ON
		t.Fatal(err)
	}
	if _, err := os.Stat(flag); err != nil || s.Off() || sent != 0 {
		t.Errorf("on: flag %v off %v sent %d", err, s.Off(), sent)
	}
	s.checked = time.Time{}
	if err := s.Set(true); err != nil { // and OFF again
		t.Fatal(err)
	}
	if _, err := os.Stat(flag); err == nil || !s.Off() || sent != 2 || len(applied) != 2 || !applied[1] {
		t.Errorf("off: flag still there or no withdraw (sent %d applied %v)", sent, applied)
	}
}
