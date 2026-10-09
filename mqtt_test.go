package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMQTTRemainingLength(t *testing.T) {
	cases := map[int][]byte{0: {0}, 127: {127}, 128: {0x80, 1}, 16383: {0xff, 0x7f}, 16384: {0x80, 0x80, 1}}
	for n, want := range cases {
		if got := mqttRemaining(n); string(got) != string(want) {
			t.Errorf("%d: % x want % x", n, got, want)
		}
	}
	// round trip through the reader
	body := make([]byte, 300)
	pkt := mqttPacket(mqttPublish, 1, body)
	typ, flags, got, err := mqttReadPacket(bufio.NewReader(strings.NewReader(string(pkt))))
	if err != nil || typ != mqttPublish || flags != 1 || len(got) != 300 {
		t.Errorf("%d %d %d %v", typ, flags, len(got), err)
	}
}

func TestMQTTConnectPacket(t *testing.T) {
	p := mqttConnectPacket(mqttOpts{ClientID: "pillowforrt", User: "ha", Pass: "pw", WillTopic: "pillowforrt/box/availability", WillPayload: "offline"})
	if p[0] != mqttConnect<<4 {
		t.Fatalf("type byte %x", p[0])
	}
	body := p[2:]
	if string(body[2:6]) != "MQTT" || body[6] != 4 {
		t.Errorf("protocol header % x", body[:7])
	}
	flags := body[7]
	if flags&0x02 == 0 || flags&0x04 == 0 || flags&0x20 == 0 || flags&0x80 == 0 || flags&0x40 == 0 {
		t.Errorf("flags %08b", flags)
	}
	if binary.BigEndian.Uint16(body[8:10]) != mqttKeepAliveS {
		t.Error("keepalive")
	}
	rest := string(body[10:])
	for _, s := range []string{"pillowforrt", "pillowforrt/box/availability", "offline", "ha", "pw"} {
		if !strings.Contains(rest, s) {
			t.Errorf("missing %q", s)
		}
	}
	// without credentials or will the flags say so
	q := mqttConnectPacket(mqttOpts{ClientID: "x"})
	if q[2+7] != 0x02 {
		t.Errorf("plain flags %08b", q[2+7])
	}
}

// fakeBroker answers CONNECT with CONNACK, records what is published and subscribed, and can push a PUBLISH to the client.
type fakeBroker struct {
	conn   net.Conn
	r      *bufio.Reader
	pubs   chan [2]string
	subs   chan string
	refuse byte
}

func newFakeBroker(t *testing.T, conn net.Conn, refuse byte) *fakeBroker {
	b := &fakeBroker{conn: conn, r: bufio.NewReader(conn), pubs: make(chan [2]string, 64), subs: make(chan string, 8), refuse: refuse}
	go func() {
		for {
			typ, _, body, err := mqttReadPacket(b.r)
			if err != nil {
				return
			}
			switch typ {
			case mqttConnect:
				conn.Write([]byte{mqttConnack << 4, 2, 0, refuse})
			case mqttPublish:
				tl := int(binary.BigEndian.Uint16(body))
				b.pubs <- [2]string{string(body[2 : 2+tl]), string(body[2+tl:])}
			case mqttSubscribe:
				tl := int(binary.BigEndian.Uint16(body[2:]))
				b.subs <- string(body[4 : 4+tl])
				conn.Write([]byte{mqttSuback << 4, 3, body[0], body[1], 0})
			case mqttPingreq:
				conn.Write([]byte{mqttPingresp << 4, 0})
			}
		}
	}()
	return b
}

func TestMQTTClientAgainstFakeBroker(t *testing.T) {
	a, b := net.Pipe()
	br := newFakeBroker(t, b, 0)
	got := make(chan [2]string, 4)
	cl, err := mqttDial(a, mqttOpts{ClientID: "c"}, func(topic string, payload []byte) { got <- [2]string{topic, string(payload)} })
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := cl.Publish("t/x", []byte("hello"), true); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-br.pubs:
		if p[0] != "t/x" || p[1] != "hello" {
			t.Errorf("%v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publish not received")
	}
	if err := cl.Subscribe("t/+/set"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-br.subs:
		if s != "t/+/set" {
			t.Errorf("%q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscribe not received")
	}
	// an incoming PUBLISH reaches the callback
	b.Write(mqttPublishPacket("t/a/set", []byte("off"), false))
	select {
	case m := <-got:
		if m[0] != "t/a/set" || m[1] != "off" {
			t.Errorf("%v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("incoming publish not delivered")
	}
	if err := cl.Ping(); err != nil {
		t.Fatal(err)
	}
	// the broker going away surfaces on Err
	b.Close()
	select {
	case <-cl.Err():
	case <-time.After(2 * time.Second):
		t.Fatal("no error after the broker closed")
	}
}

func TestMQTTConnectRefused(t *testing.T) {
	a, b := net.Pipe()
	newFakeBroker(t, b, 5)
	if _, err := mqttDial(a, mqttOpts{ClientID: "c", User: "u", Pass: "p"}, nil); err == nil || !strings.Contains(err.Error(), "user name or password") {
		t.Errorf("err %v", err)
	}
}

func TestHassEntitiesAndCommands(t *testing.T) {
	es := hassEntities("pillowforrt", "box")
	seen := map[string]bool{}
	for _, e := range es {
		if e.Config["state_topic"] != "pillowforrt/box/state" || e.Config["availability_topic"] != "pillowforrt/box/availability" || e.Config["unique_id"] == "" {
			t.Errorf("%s: %v", e.Object, e.Config)
		}
		if seen[e.Config["unique_id"].(string)] {
			t.Errorf("duplicate unique_id %s", e.Config["unique_id"])
		}
		seen[e.Config["unique_id"].(string)] = true
	}
	if len(es) < 10 {
		t.Errorf("only %d entities", len(es))
	}
	tr := hassTrackerConfig("pillowforrt", "box", "AA:BB:CC:DD:EE:FF", "Ben's laptop")
	if tr["state_topic"] != "pillowforrt/box/dev/aabbccddeeff/presence" || tr["source_type"] != "router" || tr["name"] != "Ben's laptop" {
		t.Errorf("%v", tr)
	}
	sw := hassSwitchConfig("pillowforrt", "box", "aa:bb:cc:dd:ee:ff", "Laptop")
	if sw["command_topic"] != "pillowforrt/box/dev/aabbccddeeff/internet/set" || sw["name"] != "Laptop internet" {
		t.Errorf("%v", sw)
	}
	if mac, ok := parseInternetCommand("pillowforrt", "box", "pillowforrt/box/dev/aabbccddeeff/internet/set"); !ok || mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("%q %v", mac, ok)
	}
	for _, bad := range []string{"pillowforrt/box/dev/aabbccddeeff/presence", "pillowforrt/box/dev/zzbbccddeeff/internet/set", "pillowforrt/box/dev/aabb/internet/set", "other/box/dev/aabbccddeeff/internet/set"} {
		if _, ok := parseInternetCommand("pillowforrt", "box", bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHassStateFrom(t *testing.T) {
	up := uplinkState{OK: true, LatencyMs: 41.26}
	in := metricsIn{Uplink: &up, Wifi24Clients: 2, Wifi5Clients: 3, UsageDown: 1.5e9, UsageUp: 0.5e9, UsageSet: true, EventsUnseen: 4,
		Sys: &sysView{Temps: []sysTemp{{"a", 31}, {"b", 44.5}}}, DNS: &dnsM{Queries: 10, Blocked: 2, Fallback: true}, VPN: &vpnStatus{Up: true}, Tor: &torView{Ready: false}}
	s := hassStateFrom(in, "last")
	if s.Uplink != "on" || s.LatencyMs != 41.3 || s.WifiClients != 5 || s.TempC != 44.5 || s.DataUsedGB != 2 || s.EventsUnseen != 4 || s.LastEvent != "last" ||
		s.DNSQueries != 10 || s.DNSBlocked != 2 || s.DNSEncrypted != "off" || s.VPN != "on" || s.Tor != "off" {
		t.Errorf("%+v", s)
	}
	if e := hassStateFrom(metricsIn{}, ""); e.Uplink != "" || e.DNSEncrypted != "off" || e.VPN != "off" {
		t.Errorf("empty: %+v", e)
	}
}
