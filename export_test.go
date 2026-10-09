package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLanAddr(t *testing.T) {
	good := map[string]string{"192.168.1.20:514": "192.168.1.20:514", " 10.0.0.5:1883 ": "10.0.0.5:1883", "127.0.0.1:9": "127.0.0.1:9", "[fd00::1]:514": "[fd00::1]:514"}
	for in, want := range good {
		got, err := lanAddr(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	bad := []string{"", "192.168.1.20", "logs.example.com:514", "8.8.8.8:514", "192.168.1.20:0", "192.168.1.20:70000", "100.64.0.1:514", "[2001:db8::1]:514"}
	for _, in := range bad {
		if _, err := lanAddr(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestToEVE(t *testing.T) {
	e := evt{ID: 7, T: 1700000000, Kind: "arp_spoof", Sev: sevAlert, Text: "aa:bb claimed the router's address", Public: "a device impersonated the router", Hash: "h7", Prev: "h6"}
	r := toEVE(e, "pillowforrt", false)
	if r.EventType != "alert" || r.Host != "pillowforrt" || r.Alert.Severity != 1 || r.Alert.GID != eveGID || r.Alert.Signature != "PillowForrT: arp spoof" {
		t.Errorf("%+v", r)
	}
	if r.Stone.Text != e.Text || r.Stone.Public != e.Public || r.Stone.Hash != "h7" || r.Stone.Prev != "h6" || r.Stone.ID != 7 {
		t.Errorf("%+v", r.Stone)
	}
	if !strings.HasPrefix(r.Timestamp, "2023-11-14T") || !strings.Contains(r.Timestamp, ".000000") {
		t.Errorf("timestamp %q", r.Timestamp)
	}
	if p := toEVE(e, "pillowforrt", true); p.Stone.Text != "" || p.Stone.Public != e.Public {
		t.Errorf("public view leaked the text: %+v", p.Stone)
	}
	if eveSID("arp_spoof") != eveSID("arp_spoof") || eveSID("arp_spoof") == eveSID("rogue_dhcp") || eveSID("x") < 1000000 || eveSID("x") >= 2000000 {
		t.Error("signature ids are not stable, distinct and in range")
	}
	if eveSeverity(sevAttention) != 2 || eveSeverity(sevInfo) != 3 {
		t.Error("severity mapping")
	}
	b, _ := json.Marshal(r)
	var back map[string]any
	if json.Unmarshal(b, &back) != nil || back["event_type"] != "alert" || back["alert"].(map[string]any)["signature_id"] == nil {
		t.Errorf("json shape: %s", b)
	}
}

func TestSyslogLine(t *testing.T) {
	e := evt{ID: 3, T: 1700000000, Kind: "rogue_dhcp", Sev: sevAttention, Text: `server "x" at [1]`, Public: "a second DHCP server answered", Hash: "abc", Prev: "def"}
	l := syslogLine(e, "pillowforrt", false)
	if !strings.HasPrefix(l, "<132>1 2023-11-14T22:13:20Z pillowforrt tinyfwd - rogue_dhcp [stone@0 id=\"3\" kind=\"rogue_dhcp\" sev=\"attention\" hash=\"abc\" prev=\"def\"] ") {
		t.Errorf("header: %s", l)
	}
	if !strings.HasSuffix(l, `server "x" at [1]`) {
		t.Errorf("message: %s", l)
	}
	if !strings.HasPrefix(syslogLine(evt{Sev: sevAlert, Kind: "k"}, "o", false), "<129>") || !strings.HasPrefix(syslogLine(evt{Sev: sevInfo, Kind: "k"}, "o", false), "<134>") {
		t.Error("severity to PRI")
	}
	if p := syslogLine(e, "pillowforrt", true); !strings.HasSuffix(p, "a second DHCP server answered") {
		t.Errorf("public: %s", p)
	}
	esc := syslogLine(evt{Kind: `a"b\c]d`, Sev: sevInfo}, "o", false)
	if !strings.Contains(esc, `kind="a\"b\\c\]d"`) {
		t.Errorf("sd escaping: %s", esc)
	}
}

func TestExportStoreSyslogAndSend(t *testing.T) {
	dir := t.TempDir()
	s := newExportStore(filepath.Join(dir, "export.json"))
	if err := s.SetSyslog(exportSyslog{Enabled: true, Addr: "logs.example.com:514"}); err == nil {
		t.Fatal("a name was accepted")
	}
	if err := s.SetSyslog(exportSyslog{Enabled: true, Addr: "192.168.1.9:514"}); err != nil {
		t.Fatal(err)
	}
	s2 := newExportStore(filepath.Join(dir, "export.json"))
	if c := s2.Cfg().Syslog; !c.Enabled || c.Addr != "192.168.1.9:514" {
		t.Errorf("not persisted: %+v", c)
	}
	// a UDP listener stands in for the collector
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	if err := s.SetSyslog(exportSyslog{Enabled: true, Addr: pc.LocalAddr().String()}); err != nil {
		t.Fatal(err)
	}
	s.sendSyslog(evt{ID: 1, T: 1700000000, Kind: "new_device", Sev: sevAttention, Text: "a new device", Public: "a device never seen before joined"})
	buf := make([]byte, 2048)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "new_device") || !strings.HasSuffix(got, "a new device") {
		t.Errorf("got %q", got)
	}
	if v := s.View(5); v.Syslog.LastErr != "" || v.Stream.Head != 5 || v.Tap.Enabled {
		t.Errorf("%+v", v)
	}
}

func TestExportStoreMQTTSettings(t *testing.T) {
	s := newExportStore(filepath.Join(t.TempDir(), "export.json"))
	if err := s.SetMQTT(exportMQTT{Enabled: true, Addr: "192.168.1.5:1883", User: "ha", Pass: "secret", NodeID: "Bad Id"}); err == nil {
		t.Error("a node id with a space was accepted")
	}
	if err := s.SetMQTT(exportMQTT{Enabled: true, Addr: "192.168.1.5:1883", User: "ha", Pass: "secret"}); err != nil {
		t.Fatal(err)
	}
	c := s.Cfg().MQTT
	if c.NodeID != "box" || c.Prefix != "pillowforrt" || c.PauseMinutes != 60 || c.Pass != "secret" {
		t.Errorf("%+v", c)
	}
	// an empty password on a later save keeps the stored one
	if err := s.SetMQTT(exportMQTT{Enabled: true, Addr: "192.168.1.5:1883", User: "ha", Control: true, PauseMinutes: 100000}); err != nil {
		t.Fatal(err)
	}
	c = s.Cfg().MQTT
	if c.Pass != "secret" || !c.Control || c.PauseMinutes != 24*60 {
		t.Errorf("%+v", c)
	}
	v := s.View(0)
	if !v.MQTT.PassSet || v.MQTT.State != "off" || strings.Contains(string(mustJSON(v)), "secret") {
		t.Errorf("view leaks or is wrong: %s", mustJSON(v))
	}
	if err := s.ClearMQTTPass(); err != nil || s.Cfg().MQTT.Pass != "" {
		t.Error("password not cleared")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestEventFeedDropsSlowSubscriber(t *testing.T) {
	f := newEventFeed()
	ch, stop := f.subscribe()
	defer stop()
	for i := 0; i < 70; i++ {
		f.publish(evt{ID: i})
	}
	n := 0
	for range ch { // closed once it fell behind
		n++
	}
	if n != 64 {
		t.Errorf("got %d buffered, want 64 then closed", n)
	}
	f.mu.Lock()
	left := len(f.subs)
	f.mu.Unlock()
	if left != 0 {
		t.Error("the slow subscriber was kept")
	}
}

func TestEventStreamBacklogAndFollow(t *testing.T) {
	dir := t.TempDir()
	old := events
	defer func() { events = old }()
	events = &eventStore{path: filepath.Join(dir, "ev.json"), cfgPath: filepath.Join(dir, "n.json"), known: filepath.Join(dir, "k.json"), lastOf: map[string]time.Time{}, now: time.Now, post: func(string, string, string, int) error { return nil }}
	events.sink = exportSink
	events.Add([]evt{{Kind: "a", Sev: sevInfo, Text: "one", Public: "p1"}, {Kind: "b", Sev: sevAlert, Text: "two", Public: "p2"}})

	// backlog only
	rr := httptest.NewRecorder()
	serveEventStream(rr, httptest.NewRequest("GET", "/api/events/stream?since=0", nil))
	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"kind":"b"`) || rr.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("backlog: %q", rr.Body.String())
	}

	// follow over a real server so the handler sees the client go away
	srv := httptest.NewServer(http.HandlerFunc(serveEventStream))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/events/stream?since=1&follow=1&public=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	time.Sleep(50 * time.Millisecond) // let the handler subscribe
	events.Add([]evt{{Kind: "c", Sev: sevAttention, Text: "three names a device", Public: "three"}})
	rd := bufio.NewReader(resp.Body)
	line, err := rd.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var rec eveRecord
	if json.Unmarshal([]byte(line), &rec) != nil || rec.Stone.Kind != "c" || rec.Stone.Text != "" || rec.Stone.Public != "three" || rec.Alert.Severity != 2 {
		t.Errorf("follow line: %s", line)
	}
}

func TestHandleExportAPI(t *testing.T) {
	dir := t.TempDir()
	oldX, oldE := exports, events
	defer func() { exports, events = oldX, oldE }()
	exports = newExportStore(filepath.Join(dir, "export.json"))
	events = &eventStore{path: filepath.Join(dir, "ev.json"), lastOf: map[string]time.Time{}, now: time.Now}
	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleExportAPI(rr, httptest.NewRequest("POST", "/api/"+path, strings.NewReader(body)), path)
		return rr
	}
	if rr := post("export/tap", `{"enabled":true}`); rr.Code != 200 || !exports.Cfg().Tap.Enabled {
		t.Errorf("tap on: %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("export/syslog", `{"enabled":true,"addr":"example.com:514"}`); rr.Code != 400 {
		t.Errorf("syslog name accepted: %d", rr.Code)
	}
	if rr := post("export/syslog/test", ``); rr.Code != 400 {
		t.Errorf("test without an address: %d", rr.Code)
	}
	rr := httptest.NewRecorder()
	handleExportAPI(rr, httptest.NewRequest("GET", "/api/export", nil), "export")
	var v exportView
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &v) != nil || !v.Tap.Enabled || v.Stream.Head != -1 {
		t.Errorf("view: %d %s", rr.Code, rr.Body.String())
	}
}
