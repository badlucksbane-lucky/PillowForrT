package main

import (
	"bufio"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// cannedAT is an atPort over scripted answers.
type cannedAT struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	log     []string
	closed  bool
}

func (c *cannedAT) Log() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.log...)
}
func (c *cannedAT) Closed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }

func (c *cannedAT) Exchange(cmd string, _ time.Duration) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, cmd)
	if e, ok := c.errs[cmd]; ok {
		return nil, e
	}
	if a, ok := c.answers[cmd]; ok {
		return a, nil
	}
	return nil, errors.New("ERROR")
}

func (c *cannedAT) Close() error { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }

func lteModem() *cannedAT {
	return &cannedAT{answers: map[string][]string{
		"AT": nil, "ATE0": nil, "AT+CEREG=2": nil, "AT+CREG=2": nil,
		"AT+COPS=3,2": nil, "AT+COPS=3,0": nil,
		"AT+COPS?":   {`+COPS: 0,2,"310410",7`},
		"AT+CEREG?":  {`+CEREG: 2,1,"1A2B","01C3D4E5",7`},
		"AT+CSQ":     {`+CSQ: 20,99`},
		"AT$QCRSRP?": {`$QCRSRP: 123,5230,"-95.60",456,5230,"-101.20"`},
	}}
}

func TestReadATAnswer(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("AT+CSQ\r\n\r\n+CSQ: 20,99\r\n\r\nOK\r\n"))
	lines, err := readATAnswer(r, "AT+CSQ")
	if err != nil || len(lines) != 1 || lines[0] != "+CSQ: 20,99" {
		t.Errorf("%v %v", lines, err)
	}
	if _, err := readATAnswer(bufio.NewReader(strings.NewReader("\r\n+CME ERROR: 30\r\n")), "AT+COPS?"); err == nil || !strings.Contains(err.Error(), "CME") {
		t.Errorf("error not surfaced: %v", err)
	}
	if _, err := readATAnswer(bufio.NewReader(strings.NewReader("+CSQ: 1,1\r\n")), "AT+CSQ"); err == nil {
		t.Error("eof without OK accepted")
	}
}

func TestParseCOPSAndPLMN(t *testing.T) {
	op, act, ok := parseCOPS([]string{`+COPS: 0,2,"310410",7`})
	if !ok || op != "310410" || act != 7 {
		t.Errorf("%q %d %v", op, act, ok)
	}
	if op, _, ok := parseCOPS([]string{`+COPS: 0,0,"AT&T",7`}); !ok || op != "AT&T" {
		t.Errorf("name: %q %v", op, ok)
	}
	if _, _, ok := parseCOPS([]string{"+COPS: 0"}); ok {
		t.Error("unregistered parsed as registered")
	}
	if _, _, ok := parseCOPS(nil); ok {
		t.Error("empty")
	}
	mcc, mnc, ok := splitPLMN("310410")
	if !ok || mcc != 310 || mnc != "410" {
		t.Errorf("%d %s", mcc, mnc)
	}
	if mcc, mnc, ok := splitPLMN("26201"); !ok || mcc != 262 || mnc != "01" {
		t.Errorf("%d %s", mcc, mnc)
	}
	for _, bad := range []string{"", "3104", "3104100", "31a410"} {
		if _, _, ok := splitPLMN(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if actTech(7) != "LTE" || actTech(0) != "GSM" || actTech(2) != "WCDMA" || actTech(11) != "NR" || actTech(-1) != "" {
		t.Error("actTech")
	}
}

func TestParseCxREG(t *testing.T) {
	tac, ci, act, reg, ok := parseCxREG([]string{`+CEREG: 2,1,"1A2B","01C3D4E5",7`})
	if !ok || !reg || tac != 0x1A2B || ci != 0x01C3D4E5 || act != 7 {
		t.Errorf("%d %d %d %v %v", tac, ci, act, reg, ok)
	}
	if tac, ci, _, reg, ok := parseCxREG([]string{`+CREG: 2,5,"00C3","1F2E"`}); !ok || !reg || tac != 0xC3 || ci != 0x1F2E {
		t.Errorf("creg: %d %d %v %v", tac, ci, reg, ok)
	}
	if _, _, _, reg, ok := parseCxREG([]string{"+CEREG: 2,2"}); ok || reg {
		t.Error("searching parsed as a cell")
	}
	if _, _, _, _, ok := parseCxREG([]string{`+CEREG: 2,1,"FFFE","FFFFFFFF",7`}); ok {
		t.Error("unknown cell id accepted")
	}
	if _, _, _, _, ok := parseCxREG([]string{"+CSQ: 1,1"}); ok {
		t.Error("wrong line")
	}
}

func TestParseCSQAndQCRSRP(t *testing.T) {
	if parseCSQ([]string{"+CSQ: 20,99"}) != -73 || parseCSQ([]string{"+CSQ: 99,99"}) != 0 || parseCSQ([]string{"+CSQ: 0,0"}) != -113 || parseCSQ(nil) != 0 {
		t.Error("csq")
	}
	e, r, ok := parseQCRSRP([]string{`$QCRSRP: 123,5230,"-95.60",456,5230,"-101.20"`})
	if !ok || e != 5230 || r != -95.6 {
		t.Errorf("%d %v %v", e, r, ok)
	}
	if _, _, ok := parseQCRSRP([]string{`$QCRSRP: 1,2,"5"`}); ok {
		t.Error("positive rsrp accepted")
	}
	if _, _, ok := parseQCRSRP([]string{"OK"}); ok {
		t.Error("nothing")
	}
}

func TestReadCellObs(t *testing.T) {
	m := lteModem()
	m.answers["AT+COPS?"] = []string{`+COPS: 0,2,"310410",7`}
	o, err := readCellObs(m, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if o.MCC != 310 || o.MNC != "410" || o.TAC != 0x1A2B || o.CI != 0x01C3D4E5 || o.Tech != "LTE" || o.RSSI != -73 || o.RSRP != -95.6 || o.EARFCN != 5230 || o.T != 1700000000 {
		t.Errorf("%+v", o)
	}
	if o.key() != "310_410_6699_29611237" {
		t.Errorf("key %s", o.key())
	}
	// the name is read when the second +COPS? answers with a name: canned answers are per command, so give the name and check it is picked when not digits
	m2 := lteModem()
	calls := 0
	m2.answers["AT+COPS?"] = nil
	m2.errs = map[string]error{}
	named := &switchingAT{inner: m2, onCOPS: func() []string {
		calls++
		if calls == 1 {
			return []string{`+COPS: 0,2,"310410",7`}
		}
		return []string{`+COPS: 0,0,"AT&T",7`}
	}}
	o, err = readCellObs(named, time.Now())
	if err != nil || o.Op != "AT&T" {
		t.Errorf("op %q %v", o.Op, err)
	}
	// older modem: no +CEREG, +CREG gives the cell, no $QCRSRP
	g := &cannedAT{answers: map[string][]string{"AT+COPS=3,2": nil, "AT+COPS?": {`+COPS: 0,2,"26201",0`}, "AT+CREG?": {`+CREG: 2,1,"00C3","1F2E"`}, "AT+CSQ": {"+CSQ: 10,0"}}}
	o, err = readCellObs(g, time.Now())
	if err != nil || o.Tech != "GSM" || o.TAC != 0xC3 || o.CI != 0x1F2E || o.RSSI != -93 || o.RSRP != 0 || o.EARFCN != 0 {
		t.Errorf("%+v %v", o, err)
	}
	// not registered
	n := &cannedAT{answers: map[string][]string{"AT+COPS?": {"+COPS: 0"}}}
	if _, err := readCellObs(n, time.Now()); err == nil || !strings.Contains(err.Error(), "registered") {
		t.Errorf("%v", err)
	}
	// registered but no cell id
	nc := &cannedAT{answers: map[string][]string{"AT+COPS?": {`+COPS: 0,2,"310410",7`}, "AT+CEREG?": {"+CEREG: 0,1"}}}
	if _, err := readCellObs(nc, time.Now()); err == nil || !strings.Contains(err.Error(), "cell id") {
		t.Errorf("%v", err)
	}
}

// switchingAT answers +COPS? differently on each call (first the PLMN, then the name).
type switchingAT struct {
	inner  *cannedAT
	onCOPS func() []string
}

func (s *switchingAT) Exchange(cmd string, d time.Duration) ([]string, error) {
	if cmd == "AT+COPS?" {
		return s.onCOPS(), nil
	}
	return s.inner.Exchange(cmd, d)
}
func (s *switchingAT) Close() error { return nil }

func TestCellStoreRecordFixAndCSV(t *testing.T) {
	dir := t.TempDir()
	s := newCellStore(filepath.Join(dir, "cells.json"), filepath.Join(dir, "towers.json"))
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	base := cellObs{MCC: 310, MNC: "410", TAC: 1, CI: 100, Tech: "LTE", Op: "AT&T", RSSI: -73}
	// no fix: stored, not exported
	o := base
	o.T = now.Unix()
	s.record(o)
	if v := s.View(); v.Count != 1 || v.WithFix != 0 || v.FixAgeS != -1 || v.Current == nil {
		t.Errorf("%+v", v)
	}
	if err := s.SetFix(0, 0, 0, 0); err == nil {
		t.Error("0,0 accepted")
	}
	if err := s.SetFix(40.7128, -74.0060, 10, 5); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	o.T = now.Unix()
	s.record(o) // same cell, now with a fix: a new row (fix state changed)
	now = now.Add(30 * time.Second)
	o.T = now.Unix()
	s.record(o) // same cell, same spot: replaces the previous row
	if v := s.View(); v.Count != 2 || v.WithFix != 1 || v.Cells != 1 {
		t.Errorf("%+v", v)
	}
	// moved 100 m: a new row
	s.SetFix(40.7137, -74.0060, 10, 5)
	now = now.Add(30 * time.Second)
	o.T = now.Unix()
	s.record(o)
	// a different cell
	o2 := base
	o2.CI, o2.T, o2.RSRP, o2.EARFCN = 200, now.Unix(), -101.2, 5230
	s.record(o2)
	v := s.View()
	if v.Count != 4 || v.WithFix != 3 || v.Cells != 2 || v.FixAgeS != 30 {
		t.Errorf("%+v", v)
	}
	// the fix goes stale
	now = now.Add(5 * time.Minute)
	o2.T = now.Unix()
	s.record(o2)
	if v := s.View(); v.WithFix != 3 || v.Count != 5 {
		t.Errorf("stale fix still applied: %+v", v)
	}
	csv := string(wigleCSV(s.obs, time.UTC))
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if !strings.HasPrefix(lines[0], "WigleWifi-1.6,appRelease=pillowforrt") || !strings.HasPrefix(lines[1], "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude") {
		t.Errorf("header: %q %q", lines[0], lines[1])
	}
	if len(lines) != 2+3 {
		t.Fatalf("rows: %d\n%s", len(lines)-2, csv)
	}
	if !strings.HasPrefix(lines[2], "310_410_1_100,AT&T,LTE,2023-11-14 22:14:20,0,0,-73,40.712800,-74.006000,10.0,5.0,,,LTE") {
		t.Errorf("row: %s", lines[2])
	}
	if !strings.Contains(lines[4], "310_410_1_200,AT&T,LTE,") || !strings.Contains(lines[4], ",5230,0,-101,40.713700,") {
		t.Errorf("rsrp row: %s", lines[4])
	}
	// persisted and reloaded
	s2 := newCellStore(filepath.Join(dir, "cells.json"), filepath.Join(dir, "towers.json"))
	if len(s2.obs) != 5 {
		t.Errorf("reload: %d", len(s2.obs))
	}
	if st, _ := os.Stat(filepath.Join(dir, "cells.json")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	s.Clear()
	if v := s.View(); v.Count != 0 || v.Current != nil {
		t.Error("clear")
	}
	s.ClearFix()
	if s.View().FixAgeS != -1 {
		t.Error("fix not cleared")
	}
}

func TestCellStoreSetAndCap(t *testing.T) {
	dir := t.TempDir()
	s := newCellStore(filepath.Join(dir, "cells.json"), filepath.Join(dir, "towers.json"))
	if err := s.Set(cellCfg{Enabled: true}); err == nil {
		t.Error("enabled without a port")
	}
	for _, bad := range []string{"smd8", "/dev/../etc/passwd", "/tmp/x"} {
		if err := s.Set(cellCfg{Port: bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := s.Set(cellCfg{Enabled: true, Port: "/dev/smd8", PeriodS: 3}); err != nil {
		t.Fatal(err)
	}
	if c := s.Cfg(); c.PeriodS != cellMinPeriodS || !c.Enabled {
		t.Errorf("%+v", c)
	}
	s2 := newCellStore(filepath.Join(dir, "cells.json"), filepath.Join(dir, "towers.json"))
	if c := s2.Cfg(); c.Port != "/dev/smd8" || c.PeriodS != cellMinPeriodS {
		t.Errorf("not persisted: %+v", c)
	}
	// the cap holds
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	for i := 0; i < cellMaxObs+50; i++ {
		s.record(cellObs{MCC: 1, MNC: "01", TAC: 1, CI: int64(i), T: 1700000000})
	}
	if len(s.obs) != cellMaxObs {
		t.Errorf("cap: %d", len(s.obs))
	}
}

func TestCellProbeAndRun(t *testing.T) {
	dir := t.TempDir()
	s := newCellStore(filepath.Join(dir, "cells.json"), filepath.Join(dir, "towers.json"))
	// the probe stats candidate paths: point one at a real file, the rest are absent
	fake := filepath.Join(dir, "smd8")
	os.WriteFile(fake, nil, 0o600)
	m := lteModem()
	s.open = func(p string) (atPort, error) {
		if p != fake {
			return nil, errors.New("nope")
		}
		return m, nil
	}
	res := s.Probe(fake)
	if res[fake] != "answers OK" {
		t.Errorf("%v", res)
	}
	if r := s.Probe("/dev/does-not-exist-xyz"); r["/dev/does-not-exist-xyz"] != "not present" {
		t.Errorf("%v", r)
	}
	// Run: enabled with the fake port, one observation lands, then the port is reopened after a transport error
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	go s.Run()
	s.mu.Lock()
	s.cfg = cellCfg{Enabled: true, Port: fake, PeriodS: cellMinPeriodS} // bypass the /dev check for the test
	s.mu.Unlock()
	s.kick <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v := s.View(); v.Count == 1 && v.PortOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	v := s.View()
	if v.Count != 1 || !v.PortOK || v.LastErr != "" || v.Current == nil || v.Current.CI != 0x01C3D4E5 {
		t.Fatalf("%+v", v)
	}
	if lg := m.Log(); lg[1] != "AT" || lg[2] != "ATE0" || lg[3] != "AT+CEREG=2" { // lg[0] is the probe
		t.Errorf("setup not sent: %v", lg[:4])
	}
	// switching off closes the port
	s.Set(cellCfg{Enabled: false, Port: "/dev/smd8"})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.View().PortOK { // m.Closed() alone would not do: the probe closed it once already
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Closed() || s.View().PortOK {
		t.Error("port not closed when switched off")
	}
}

func TestHandleCellAPI(t *testing.T) {
	dir := t.TempDir()
	old := towers
	defer func() { towers = old }()
	towers = newCellStore(filepath.Join(dir, "cells.json"), filepath.Join(dir, "towers.json"))
	post := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handleCellAPI(rr, httptest.NewRequest("POST", "/api/"+path, strings.NewReader(body)), path)
		return rr
	}
	if rr := post("towers/fix", `{"lat":51.5,"lon":-0.12,"acc":8}`); rr.Code != 200 {
		t.Errorf("fix: %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("towers/fix", `{"lat":99,"lon":0}`); rr.Code != 400 {
		t.Errorf("bad fix accepted: %d", rr.Code)
	}
	if rr := post("towers/probe", `{"port":"../x"}`); rr.Code != 400 {
		t.Errorf("bad probe port: %d", rr.Code)
	}
	towers.record(cellObs{MCC: 234, MNC: "15", TAC: 5, CI: 9, Tech: "LTE", T: time.Now().Unix()})
	rr := httptest.NewRecorder()
	handleCellAPI(rr, httptest.NewRequest("GET", "/api/towers/wigle.csv", nil), "towers/wigle.csv")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "234_15_5_9,,LTE,") || !strings.Contains(rr.Header().Get("Content-Disposition"), ".csv") {
		t.Errorf("csv: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handleCellAPI(rr, httptest.NewRequest("GET", "/api/towers", nil), "towers")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"with_fix":1`) || !strings.Contains(rr.Body.String(), `"candidates"`) {
		t.Errorf("view: %s", rr.Body.String())
	}
	if rr := post("towers/clear", ""); rr.Code != 200 || towers.View().Count != 0 {
		t.Error("clear")
	}
}

func TestMoved(t *testing.T) {
	if d := moved(40.7128, -74.0060, 40.7137, -74.0060); d < 95 || d > 105 {
		t.Errorf("100 m north came out as %.1f", d)
	}
	if d := moved(40.7128, -74.0060, 40.7128, -74.0060); d != 0 {
		t.Error("same point")
	}
}
