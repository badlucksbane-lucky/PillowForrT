package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// a query with an OPT record holding the given options (code, data)
func queryWithOpt(name string, opts ...[]byte) []byte {
	q := mkQuery(name, qtA, 7, true)
	binary.BigEndian.PutUint16(q[10:12], 1)
	var rd []byte
	for _, o := range opts {
		rd = append(rd, o...)
	}
	q = append(q, 0, 0, byte(qtOPT), 0x10, 0, 0, 0, 0, 0, byte(len(rd)>>8), byte(len(rd)))
	return append(q, rd...)
}

func opt(code uint16, data ...byte) []byte {
	b := []byte{byte(code >> 8), byte(code), byte(len(data) >> 8), byte(len(data))}
	return append(b, data...)
}

func TestSplitClient(t *testing.T) {
	ecs4 := opt(8, 0, 1, 32, 0, 192, 168, 1, 40)
	cookie := opt(10, 1, 2, 3, 4, 5, 6, 7, 8)
	q := queryWithOpt("ads.example.com", cookie, ecs4)
	dq, err := parseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	client, out := splitClient(q, dq.QEnd)
	if client != "192.168.1.40" {
		t.Fatalf("client %q", client)
	}
	if bytes.Contains(out, ecs4) || !bytes.Contains(out, cookie) {
		t.Fatal("ECS must be stripped and the other option kept")
	}
	if _, err := parseQuery(out); err != nil {
		t.Fatalf("stripped query does not parse: %v", err)
	}
	if rd := binary.BigEndian.Uint16(out[len(out)-len(cookie)-2 : len(out)-len(cookie)]); int(rd) != len(cookie) {
		t.Fatalf("rdlen %d want %d", rd, len(cookie))
	}
	// IPv6, /128
	ecs6 := opt(8, append([]byte{0, 2, 128, 0}, bytes.Repeat([]byte{0xfe}, 16)...)...)
	q6 := queryWithOpt("a.example.com", ecs6)
	d6, _ := parseQuery(q6)
	if c, _ := splitClient(q6, d6.QEnd); c != "fefe:fefe:fefe:fefe:fefe:fefe:fefe:fefe" {
		t.Fatalf("ipv6 client %q", c)
	}
	// no OPT / OPT without ECS: untouched
	plain := mkQuery("a.example.com", qtA, 1, true)
	if c, o := splitClient(plain, len(plain)); c != "" || !bytes.Equal(o, plain) {
		t.Fatal("plain query changed")
	}
	noecs := queryWithOpt("a.example.com", cookie)
	dn, _ := parseQuery(noecs)
	if c, o := splitClient(noecs, dn.QEnd); c != "" || !bytes.Equal(o, noecs) {
		t.Fatal("query without ECS changed")
	}
	for n := 0; n < len(q); n++ { // truncation never panics
		splitClient(q[:n], dq.QEnd)
	}
}

func TestPerDeviceCounts(t *testing.T) {
	doh, pool := newFakeDoH(t)
	plain, _ := fakePlain(t)
	p := testProxy(t, doh, pool, plain)
	ecs := opt(8, 0, 1, 32, 0, 192, 168, 1, 40)
	p.Handle(queryWithOpt("example.com", ecs))
	p.Handle(queryWithOpt("example.com", ecs))
	if b, _ := doh.last.Load().([]byte); len(b) == 0 || bytes.Contains(b, ecs) {
		t.Fatal("the device address reached the upstream resolver")
	}
	sn := p.Stats.Snapshot(5, 5)
	if len(sn.Clients) != 1 || sn.Clients[0].IP != "192.168.1.40" || sn.Clients[0].Queries != 2 {
		t.Fatalf("clients: %+v", sn.Clients)
	}
	if len(sn.Recent) == 0 || sn.Recent[0].Client != "192.168.1.40" {
		t.Fatal("event lacks the client")
	}
}

func TestDeviceNames(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "leases"), []byte("1790 aa:bb 192.168.1.150 laptop 01:aa\n1790 cc:dd 192.168.1.40 * 01:cc\nduid 00:01\n"), 0o644)
	os.WriteFile(filepath.Join(d, "hosts"), []byte("# c\nac:3e,192.168.1.10,phone-c\n"), 0o644)
	m := deviceNames(filepath.Join(d, "leases"), filepath.Join(d, "hosts"))
	if m["192.168.1.150"] != "laptop" || m["192.168.1.10"] != "phone-c" || m["192.168.1.40"] != "" {
		t.Fatalf("%v", m)
	}
}

func TestPerDeviceThroughProxy(t *testing.T) {
	doh, pool := newFakeDoH(t)
	plain, _ := fakePlain(t)
	p := testProxy(t, doh, pool, plain) // oisd list blocks blocked.example.com
	p.Filter.SetDeviceMode("192.168.1.40", "off")
	kid := opt(8, 0, 1, 32, 0, 192, 168, 1, 40)
	other := opt(8, 0, 1, 32, 0, 192, 168, 1, 20)
	if addrOf(p.Handle(queryWithOpt("blocked.example.com", kid))) == "0.0.0.0" {
		t.Error("the device with the filter off was blocked")
	}
	if addrOf(p.Handle(queryWithOpt("blocked.example.com", other))) != "0.0.0.0" {
		t.Error("another device was not blocked")
	}
}

func TestIPv6TiedToDevice(t *testing.T) {
	n := newNeighbours()
	n.arp = func() string {
		return "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.20    0x1         0x2         00:00:5e:00:53:08     *        bridge0\n192.168.1.99    0x1         0x0         00:00:00:00:00:00     *        bridge0\n"
	}
	n.ndp = func() string {
		return "fe80::c443:b2ff:fe14:e0b4 dev bridge0 lladdr 00:00:5e:00:53:08 REACHABLE\n2600:1::5 dev bridge0 lladdr 00:00:5e:00:53:08 STALE\nfe80::dead dev bridge0 lladdr 11:22:33:44:55:66 STALE\nfe80::1 dev bridge0  FAILED\n"
	}
	for in, want := range map[string]string{
		"fe80::c443:b2ff:fe14:e0b4": "192.168.1.20", // link-local, MAC from the neighbour table
		"2600:1::5":                 "192.168.1.20", // a global address of the same device
		"fe80::dead":                "fe80::dead",   // MAC known, no IPv4 for it: unchanged
		"fe80::beef":                "fe80::beef",   // unknown: unchanged
		"192.168.1.5":               "192.168.1.5",  // IPv4 is never touched
		"not-an-ip":                 "not-an-ip",
	} {
		if got := n.canonical(in); got != want {
			t.Errorf("canonical(%s) = %s, want %s", in, got, want)
		}
	}
	doh, pool := newFakeDoH(t)
	plain, _ := fakePlain(t)
	p := testProxy(t, doh, pool, plain)
	p.Neigh = n
	p.Filter.SetDeviceMode("192.168.1.20", "off")
	v6 := opt(8, append([]byte{0, 2, 128, 0}, net.ParseIP("fe80::c443:b2ff:fe14:e0b4").To16()...)...)
	if addrOf(p.Handle(queryWithOpt("blocked.example.com", v6))) == "0.0.0.0" {
		t.Error("an IPv6 query from a device with the filter off was blocked")
	}
	if sn := p.Stats.Snapshot(3, 3); len(sn.Clients) != 1 || sn.Clients[0].IP != "192.168.1.20" {
		t.Errorf("clients: %+v", sn.Clients)
	}
}
