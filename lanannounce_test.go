package main

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Builders for mDNS responses.

func mdnsName(s string) []byte {
	var out []byte
	for _, p := range strings.Split(s, ".") {
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	return append(out, 0)
}

type mdnsRR struct {
	name string
	typ  uint16
	rd   []byte
}

func mdnsResponse(rrs ...mdnsRR) []byte {
	m := []byte{0x00, 0x00, 0x84, 0x00, 0, 0, byte(len(rrs) >> 8), byte(len(rrs)), 0, 0, 0, 0}
	for _, r := range rrs {
		m = append(m, mdnsName(r.name)...)
		m = append(m, byte(r.typ>>8), byte(r.typ), 0x80, 0x01, 0, 0, 0x11, 0x94, byte(len(r.rd)>>8), byte(len(r.rd)))
		m = append(m, r.rd...)
	}
	return m
}

func mdnsPTR(name, target string) mdnsRR   { return mdnsRR{name, 12, mdnsName(target)} }
func mdnsA(name string, ip [4]byte) mdnsRR { return mdnsRR{name, 1, ip[:]} }
func mdnsSRV(name string, port int, target string) mdnsRR {
	return mdnsRR{name, 33, append([]byte{0, 0, 0, 0, byte(port >> 8), byte(port)}, mdnsName(target)...)}
}

type laHarness struct {
	w      *lanAnnounceWatch
	events []evt
	now    time.Time
}

func newLAHarness() *laHarness {
	h := &laHarness{now: time.Unix(1_700_000_000, 0)}
	h.w = newLANAnnounceWatch("")
	h.w.now = func() time.Time { return h.now }
	h.w.emit = func(e evt) { h.events = append(h.events, e) }
	h.w.macOf = func(string) string { return "" }
	h.w.nameOf = func(string) string { return "" }
	return h
}

func (h *laHarness) mdns(src string, payload []byte) {
	h.w.observe(udpFrame{Src: src, Dst: "224.0.0.251", SrcPort: 5353, DstPort: 5353, Payload: payload}, h.now)
}

func (h *laHarness) ssdp(src, msg string) {
	h.w.observe(udpFrame{Src: src, Dst: "239.255.255.250", SrcPort: 40000, DstPort: 1900, Payload: []byte(strings.ReplaceAll(msg, "\n", "\r\n"))}, h.now)
}

func TestLANAnnounceMDNSInventory(t *testing.T) {
	h := newLAHarness()
	h.mdns("192.168.1.30", mdnsResponse(
		mdnsPTR("_googlecast._tcp.local", "Living Room._googlecast._tcp.local"),
		mdnsSRV("Living Room._googlecast._tcp.local", 8009, "tv.local"),
		mdnsA("tv.local", [4]byte{192, 168, 1, 30}),
		mdnsPTR("_services._dns-sd._udp.local", "_googlecast._tcp.local"),
	))
	d := h.w.st.Devices["192.168.1.30"]
	if d == nil || d.Host != "tv.local" || len(d.Services) != 1 || d.Services[0].Type != "_googlecast._tcp" || d.Services[0].Instance != "Living Room" || d.Services[0].Port != 8009 {
		t.Fatalf("inventory: %+v", d)
	}
	if len(h.events) != 1 || h.events[0].Kind != "lan_service_new" || h.events[0].Sev != sevInfo {
		t.Fatalf("first announcement of a service is an info event: %+v", h.events)
	}
	// the same announcement again is silent
	h.now = h.now.Add(2 * time.Hour)
	h.mdns("192.168.1.30", mdnsResponse(mdnsPTR("_googlecast._tcp.local", "Living Room._googlecast._tcp.local")))
	if len(h.events) != 1 {
		t.Fatalf("a repeat is silent: %+v", h.events)
	}
	// a query is not inventory
	q := mdnsResponse()
	q[2] = 0x00
	h.mdns("192.168.1.31", q)
	if _, had := h.w.st.Devices["192.168.1.31"]; had {
		t.Fatal("a query should not create a device")
	}
	// a response from outside the LAN is ignored
	h.mdns("10.0.0.9", mdnsResponse(mdnsPTR("_http._tcp.local", "x._http._tcp.local")))
	if _, had := h.w.st.Devices["10.0.0.9"]; had {
		t.Fatal("outside the LAN is out of scope")
	}
}

func TestLANAnnounceHostConflict(t *testing.T) {
	h := newLAHarness()
	h.mdns("192.168.1.30", mdnsResponse(mdnsA("printer.local", [4]byte{192, 168, 1, 30})))
	h.now = h.now.Add(time.Minute)
	h.mdns("192.168.1.77", mdnsResponse(mdnsA("printer.local", [4]byte{192, 168, 1, 77})))
	if len(h.events) != 1 || h.events[0].Kind != "lan_host_conflict" || h.events[0].Sev != sevAttention {
		t.Fatalf("two addresses answering for one name within minutes: %+v", h.events)
	}
	if h.w.st.Hosts["printer.local"] != "192.168.1.77" {
		t.Fatal("the newest answerer holds the name")
	}
	// a device answering with an address that is not its own is neither inventory nor a conflict
	h.mdns("192.168.1.90", mdnsResponse(mdnsA("printer.local", [4]byte{192, 168, 1, 77})))
	if len(h.events) != 1 || h.w.st.Devices["192.168.1.90"].Host != "" {
		t.Fatalf("an A record for another address is ignored: %+v", h.events)
	}
	// the old holder gone for a long time: a name moving is just a lease change, no event
	h2 := newLAHarness()
	h2.mdns("192.168.1.30", mdnsResponse(mdnsA("laptop.local", [4]byte{192, 168, 1, 30})))
	h2.now = h2.now.Add(3 * time.Hour)
	h2.mdns("192.168.1.31", mdnsResponse(mdnsA("laptop.local", [4]byte{192, 168, 1, 31})))
	if len(h2.events) != 0 {
		t.Fatalf("a name moving after hours of silence is not a conflict: %+v", h2.events)
	}
}

func TestLANAnnounceSSDP(t *testing.T) {
	h := newLAHarness()
	h.ssdp("192.168.1.40", "NOTIFY * HTTP/1.1\nHOST: 239.255.255.250:1900\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\nNTS: ssdp:alive\nUSN: uuid:abc::urn:schemas-upnp-org:device:MediaRenderer:1\nLOCATION: http://192.168.1.40:49152/desc.xml\nSERVER: Linux/4.9 UPnP/1.0 Foo/1.2\n\n")
	d := h.w.st.Devices["192.168.1.40"]
	if d == nil || d.Server != "Linux/4.9 UPnP/1.0 Foo/1.2" || len(d.Services) != 1 || d.Services[0].Type != "urn:schemas-upnp-org:device:MediaRenderer:1" || d.Services[0].Via != "ssdp" {
		t.Fatalf("ssdp inventory: %+v", d)
	}
	if len(h.events) != 1 || h.events[0].Kind != "lan_service_new" {
		t.Fatalf("events: %+v", h.events)
	}
	// root device and bare uuid announcements add nothing
	h.ssdp("192.168.1.40", "NOTIFY * HTTP/1.1\nNT: upnp:rootdevice\nNTS: ssdp:alive\nLOCATION: http://192.168.1.40:49152/desc.xml\n\n")
	h.ssdp("192.168.1.40", "NOTIFY * HTTP/1.1\nNT: uuid:abc\nNTS: ssdp:alive\nLOCATION: http://192.168.1.40:49152/desc.xml\n\n")
	if len(d.Services) != 1 || len(h.events) != 1 {
		t.Fatalf("root/uuid should add nothing: %+v %+v", d.Services, h.events)
	}
	// byebye is not an announcement
	h.ssdp("192.168.1.41", "NOTIFY * HTTP/1.1\nNT: urn:schemas-upnp-org:device:Basic:1\nNTS: ssdp:byebye\n\n")
	if len(h.w.st.Devices["192.168.1.41"].Services) != 0 {
		t.Fatal("byebye should not add a service")
	}
	// a description hosted elsewhere
	h.ssdp("192.168.1.42", "NOTIFY * HTTP/1.1\nNT: urn:schemas-upnp-org:device:Basic:1\nNTS: ssdp:alive\nLOCATION: http://192.168.1.1:80/desc.xml\n\n")
	kinds := []string{}
	for _, e := range h.events {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != "lan_service_new,lan_ssdp_elsewhere,lan_service_new" {
		t.Fatalf("events: %v", kinds)
	}
	// M-SEARCH ssdp:all is counted, never an event
	before := len(h.events)
	h.ssdp("192.168.1.50", "M-SEARCH * HTTP/1.1\nHOST: 239.255.255.250:1900\nMAN: \"ssdp:discover\"\nMX: 1\nST: ssdp:all\n\n")
	h.ssdp("192.168.1.50", "M-SEARCH * HTTP/1.1\nST: urn:dial-multiscreen-org:service:dial:1\n\n")
	if s := h.w.st.Devices["192.168.1.50"]; s.Searches != 1 || len(h.events) != before {
		t.Fatalf("searches=%d events=%d", s.Searches, len(h.events))
	}
	// something that is not SSDP
	h.ssdp("192.168.1.51", "GET / HTTP/1.1\n\n")
	if _, had := h.w.st.Devices["192.168.1.51"]; had {
		t.Fatal("not SSDP, not a device")
	}
}

func TestLANAnnounceCapsAndView(t *testing.T) {
	h := newLAHarness()
	for i := 0; i < lanDevicesMax+10; i++ {
		h.now = h.now.Add(time.Second)
		h.w.device("192.168.1."+strconv.Itoa(2+i%250), h.now)
	}
	if len(h.w.st.Devices) > lanDevicesMax {
		t.Fatalf("devices grew to %d", len(h.w.st.Devices))
	}
	d := h.w.device("192.168.1.200", h.now)
	for i := 0; i < lanServicesMax+5; i++ {
		h.now = h.now.Add(time.Second)
		h.w.addService(d, lanService{Type: "_t" + strconv.Itoa(i) + "._tcp", Via: "mdns"}, h.now)
	}
	if len(d.Services) != lanServicesMax {
		t.Fatalf("services = %d", len(d.Services))
	}
	h.now = h.now.Add(time.Second)
	h.w.device("192.168.1.200", h.now)
	v := h.w.View()
	if len(v.Devices) == 0 || v.Devices[0].IP != "192.168.1.200" {
		t.Fatalf("view sorted newest first: %+v", v.Devices[0].IP)
	}
}

func TestLANAnnounceHelpers(t *testing.T) {
	if typ, inst, ok := serviceType("Living Room._googlecast._tcp.local"); !ok || typ != "_googlecast._tcp" || inst != "Living Room" {
		t.Fatalf("serviceType: %q %q %v", typ, inst, ok)
	}
	if typ, inst, ok := serviceType("Office Printer._ipp._tcp.local"); !ok || typ != "_ipp._tcp" || inst != "Office Printer" {
		t.Fatalf("serviceType: %q %q %v", typ, inst, ok)
	}
	if _, _, ok := serviceType("tv.local"); ok {
		t.Fatal("a host name is not a service instance")
	}
	if h := locationHost("http://192.168.1.40:49152/desc.xml"); h != "192.168.1.40" {
		t.Fatalf("locationHost: %q", h)
	}
	if h := locationHost("http://box.local/x"); h != "box.local" {
		t.Fatalf("locationHost: %q", h)
	}
	// compression pointers in names
	m := mdnsResponse(mdnsPTR("_http._tcp.local", "x._http._tcp.local"))
	// append a record whose name is a pointer to offset 12 (the first record's name)
	m[7]++
	m = append(m, 0xc0, 12, 0, 12, 0x80, 0x01, 0, 0, 0, 10, 0, 2, 0xc0, 12)
	_, recs, ok := parseMDNS(m)
	if !ok || len(recs) != 2 || recs[1].Name != "_http._tcp.local" || recs[1].Target != "_http._tcp.local" {
		t.Fatalf("compressed names: %+v %v", recs, ok)
	}
	if _, _, ok := parseMDNS([]byte{1, 2, 3}); ok {
		t.Fatal("short message")
	}
}

func TestLANAnnouncePersistence(t *testing.T) {
	path := t.TempDir() + "/lan.json"
	w := newLANAnnounceWatch(path)
	w.emit = func(evt) {}
	w.macOf = func(string) string { return "" }
	w.nameOf = func(string) string { return "" }
	w.observe(udpFrame{Src: "192.168.1.30", DstPort: 5353, Payload: mdnsResponse(mdnsPTR("_http._tcp.local", "cam._http._tcp.local"))}, time.Now())
	w.save()
	w2 := newLANAnnounceWatch(path)
	if d := w2.st.Devices["192.168.1.30"]; d == nil || len(d.Services) != 1 {
		t.Fatalf("inventory should survive a restart: %+v", d)
	}
}
