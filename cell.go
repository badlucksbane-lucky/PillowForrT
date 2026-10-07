package main

// Tower telemetry for WiGLE. The modem is asked, over its AT port, which cell it is camped on (PLMN, tracking area, cell id, technology, signal) every so often, each
// answer is stored as an observation, a companion computer or phone posts the location it has (the hotspot has no GPS), and the observations with a location are
// served as a WiGLE CSV (the WigleWifi-1.6 upload format, one cell row per observation) for you to upload or keep. That is all this does: it is telemetry out, not
// a detector. No IMSI-catcher logic, no 2G-downgrade alarm, no event is raised from it; WiGLE's own map, or whatever you feed the CSV to, does the comparing.
//
// How the modem is read: AT commands on a serial port of the modem (-cell-at, default empty = off). On this Qualcomm MDM9607 unit the candidates are /dev/smd8,
// /dev/smd11 and /dev/smd7; the page's "probe" tries each with a bare AT and reports which one answers OK, since the port may differ by firmware and may be held
// open by a stock daemon. The commands are the standard ones (+COPS, +CEREG/+CREG with location reporting on, +CSQ) plus Qualcomm's $QCRSRP for RSRP and EARFCN
// when it answers; whatever the modem does not understand is simply left blank. Everything that parses is pure and unit-tested with canned answers; the serial I/O
// is the only part that needs the unit.
//
// Where the location comes from: POST /api/cell/fix {lat, lon, alt, acc} from anything that knows where the box is: scripts/gps-feed.sh reads gpsd on a companion,
// a phone can post from Tasker or a shortcut, a parked box can be given a fixed position once. A fix is held in RAM only and is used for 90 seconds; observations
// taken without a fresh fix are stored and shown but left out of the WiGLE CSV, which needs one.
//
// Privacy: the cell and the location are what the carrier already knows about this box, but they are also where you are, so they go nowhere by themselves. They
// are not in /status.json, /metrics, an event, a notification or the syslog or MQTT exports of events; the only ways out are this page's CSV and (if you turned it
// on) the Home Assistant state, which is LAN-only. Observations live in /data/proxy/cells.json (0600), capped, and "Clear" deletes them.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	cellMaxObs     = 5000
	cellFixFreshS  = 90
	cellDefPeriodS = 60
	cellMinPeriodS = 15
)

var cellPortCandidates = []string{"/dev/smd8", "/dev/smd11", "/dev/smd7", "/dev/ttyUSB2", "/dev/ttyUSB1", "/dev/at_mdm0"}

type cellCfg struct {
	Enabled bool   `json:"enabled"`
	Port    string `json:"port"`
	PeriodS int    `json:"period_s"`
}

// cellObs is one look at the serving cell. Tech is GSM, WCDMA, LTE or NR (WiGLE's words).
type cellObs struct {
	T      int64   `json:"t"`
	MCC    int     `json:"mcc"`
	MNC    string  `json:"mnc"` // kept as text: "01" and "1" are different networks
	TAC    int     `json:"tac"` // tracking area (LTE/NR) or location area (GSM/WCDMA)
	CI     int64   `json:"ci"`  // cell identity
	Tech   string  `json:"tech"`
	Op     string  `json:"op,omitempty"`
	RSSI   int     `json:"rssi,omitempty"` // dBm from +CSQ, 0 when unknown
	RSRP   float64 `json:"rsrp,omitempty"` // dBm from $QCRSRP, 0 when unknown
	EARFCN int     `json:"earfcn,omitempty"`
	Fix    bool    `json:"fix"`
	Lat    float64 `json:"lat,omitempty"`
	Lon    float64 `json:"lon,omitempty"`
	Alt    float64 `json:"alt,omitempty"`
	Acc    float64 `json:"acc,omitempty"`
}

func (o cellObs) key() string { return fmt.Sprintf("%d_%s_%d_%d", o.MCC, o.MNC, o.TAC, o.CI) }

type cellFix struct {
	Lat, Lon, Alt, Acc float64
	At                 time.Time
}

// atPort is what the modem looks like to the reader: a line-based request/response channel.
type atPort interface {
	Exchange(cmd string, timeout time.Duration) ([]string, error) // the answer lines up to and excluding the final OK; ERROR is an error
	Close() error
}

// serialAT talks to a tty or SMD device file with read deadlines.
type serialAT struct {
	f *os.File
	r *bufio.Reader
}

func openSerialAT(path string) (atPort, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return &serialAT{f: f, r: bufio.NewReader(f)}, nil
}

func (s *serialAT) Close() error { return s.f.Close() }

func (s *serialAT) Exchange(cmd string, timeout time.Duration) ([]string, error) {
	s.f.SetDeadline(time.Now().Add(timeout))
	if _, err := s.f.Write([]byte(cmd + "\r")); err != nil {
		return nil, err
	}
	return readATAnswer(s.r, cmd)
}

// readATAnswer collects the lines of one answer: echo of the command is dropped, blank lines are dropped, OK ends it, ERROR (or +CME ERROR) fails it.
func readATAnswer(r *bufio.Reader, cmd string) ([]string, error) {
	var lines []string
	for {
		l, err := r.ReadString('\n')
		l = strings.TrimSpace(l)
		if l != "" {
			switch {
			case l == "OK":
				return lines, nil
			case l == "ERROR" || strings.HasPrefix(l, "+CME ERROR") || strings.HasPrefix(l, "+CMS ERROR"):
				return lines, errors.New(l)
			case l == cmd:
			default:
				lines = append(lines, l)
			}
		}
		if err != nil {
			if len(lines) > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
				return lines, errors.New("no OK before the timeout")
			}
			return lines, err
		}
	}
}

// ---- parsing (pure) ----

var atQuoted = regexp.MustCompile(`"([^"]*)"`)

// parseCOPS reads +COPS: <mode>,<format>,"<oper>",<AcT>. With format 2 oper is the PLMN digits; with format 0 the long name.
func parseCOPS(lines []string) (oper string, act int, ok bool) {
	for _, l := range lines {
		if !strings.HasPrefix(l, "+COPS:") {
			continue
		}
		q := atQuoted.FindStringSubmatch(l)
		if q == nil {
			return "", -1, false // not registered: "+COPS: 0"
		}
		act = -1
		f := strings.Split(strings.TrimSpace(strings.TrimPrefix(l, "+COPS:")), ",")
		if len(f) >= 4 {
			act, _ = strconv.Atoi(strings.TrimSpace(f[3]))
		}
		return q[1], act, true
	}
	return "", -1, false
}

// splitPLMN turns "310410" into 310 and "410", "26201" into 262 and "01".
func splitPLMN(plmn string) (int, string, bool) {
	if len(plmn) != 5 && len(plmn) != 6 {
		return 0, "", false
	}
	for _, c := range plmn {
		if c < '0' || c > '9' {
			return 0, "", false
		}
	}
	mcc, _ := strconv.Atoi(plmn[:3])
	return mcc, plmn[3:], true
}

// actTech maps 3GPP 27.007 <AcT> to WiGLE's technology names.
func actTech(act int) string {
	switch act {
	case 0, 1, 3:
		return "GSM"
	case 2, 4, 5, 6:
		return "WCDMA"
	case 7, 8, 9:
		return "LTE"
	case 10, 11, 12, 13:
		return "NR"
	}
	return ""
}

// parseCxREG reads +CEREG/+CREG/+CGREG: <n>,<stat>[,"<lac/tac>","<ci>"[,<AcT>]]: registered (stat 1 or 5), the area and cell in hex, and the AcT when present.
func parseCxREG(lines []string) (tac int, ci int64, act int, registered, ok bool) {
	for _, l := range lines {
		if !(strings.HasPrefix(l, "+CEREG:") || strings.HasPrefix(l, "+CREG:") || strings.HasPrefix(l, "+CGREG:")) {
			continue
		}
		_, rest, _ := strings.Cut(l, ":")
		f := strings.Split(rest, ",")
		for i := range f {
			f[i] = strings.Trim(strings.TrimSpace(f[i]), `"`)
		}
		if len(f) < 2 {
			return 0, 0, -1, false, false
		}
		st, _ := strconv.Atoi(f[1])
		registered = st == 1 || st == 5
		act = -1
		if len(f) >= 4 && f[2] != "" && f[3] != "" {
			t, e1 := strconv.ParseInt(f[2], 16, 32)
			c, e2 := strconv.ParseInt(f[3], 16, 64)
			if e1 == nil && e2 == nil && c != 0xFFFFFFFF && c != 0xFFFF {
				tac, ci, ok = int(t), c, true
			}
		}
		if len(f) >= 5 {
			act, _ = strconv.Atoi(f[4])
		}
		return
	}
	return 0, 0, -1, false, false
}

// parseCSQ: +CSQ: <rssi>,<ber>; rssi 0..31 maps to -113..-51 dBm, 99 is unknown.
func parseCSQ(lines []string) int {
	for _, l := range lines {
		if strings.HasPrefix(l, "+CSQ:") {
			f := strings.Split(strings.TrimSpace(strings.TrimPrefix(l, "+CSQ:")), ",")
			n, err := strconv.Atoi(strings.TrimSpace(f[0]))
			if err != nil || n < 0 || n > 31 {
				return 0
			}
			return -113 + 2*n
		}
	}
	return 0
}

// parseQCRSRP: $QCRSRP: <pci>,<earfcn>,"<rsrp>"[,<pci>,<earfcn>,"<rsrp>"...]; the first triple is the serving cell.
func parseQCRSRP(lines []string) (earfcn int, rsrp float64, ok bool) {
	for _, l := range lines {
		if !strings.HasPrefix(l, "$QCRSRP:") {
			continue
		}
		f := strings.Split(strings.TrimSpace(strings.TrimPrefix(l, "$QCRSRP:")), ",")
		if len(f) < 3 {
			return 0, 0, false
		}
		e, err1 := strconv.Atoi(strings.TrimSpace(f[1]))
		r, err2 := strconv.ParseFloat(strings.Trim(strings.TrimSpace(f[2]), `"`), 64)
		if err1 != nil || err2 != nil || r >= 0 || r < -160 {
			return 0, 0, false
		}
		return e, r, true
	}
	return 0, 0, false
}

// readCellObs asks the modem one round of questions and assembles an observation. Each command's failure is tolerated; the observation is usable when the PLMN
// and a cell id came back. The port is expected to have had +CEREG=2 / +CREG=2 set once (setupPort).
func readCellObs(p atPort, now time.Time) (cellObs, error) {
	o := cellObs{T: now.Unix()}
	to := 3 * time.Second
	p.Exchange("AT+COPS=3,2", to)
	lines, err := p.Exchange("AT+COPS?", to)
	if err != nil && len(lines) == 0 {
		return o, fmt.Errorf("+COPS: %v", err)
	}
	plmn, act, ok := parseCOPS(lines)
	if !ok {
		return o, errors.New("not registered on a network")
	}
	if o.MCC, o.MNC, ok = splitPLMN(plmn); !ok {
		return o, errors.New("the operator came back as a name, not a PLMN: " + plmn)
	}
	o.Tech = actTech(act)
	if lines, err := p.Exchange("AT+COPS=3,0", to); err == nil || len(lines) > 0 {
		if lines, _ := p.Exchange("AT+COPS?", to); lines != nil {
			if name, _, ok := parseCOPS(lines); ok && !isDigits(name) {
				o.Op = name
			}
		}
	}
	got := false
	for _, cmd := range []string{"AT+CEREG?", "AT+CREG?", "AT+CGREG?"} {
		lines, _ := p.Exchange(cmd, to)
		if tac, ci, a, reg, ok := parseCxREG(lines); ok && reg {
			o.TAC, o.CI, got = tac, ci, true
			if o.Tech == "" && a >= 0 {
				o.Tech = actTech(a)
			}
			break
		}
	}
	if !got {
		return o, errors.New("the modem gave no cell id (is location reporting on? +CEREG=2)")
	}
	if lines, _ := p.Exchange("AT+CSQ", to); lines != nil {
		o.RSSI = parseCSQ(lines)
	}
	if lines, _ := p.Exchange("AT$QCRSRP?", to); lines != nil {
		if e, r, ok := parseQCRSRP(lines); ok {
			o.EARFCN, o.RSRP = e, r
		}
	}
	if o.Tech == "" {
		o.Tech = "LTE"
	}
	return o, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// setupPort checks the port answers and switches location reporting on; the result of the switches does not matter (an older modem may lack +CEREG).
func setupPort(p atPort) error {
	if _, err := p.Exchange("AT", 2*time.Second); err != nil {
		return errors.New("no answer to AT: " + err.Error())
	}
	p.Exchange("ATE0", 2*time.Second)
	p.Exchange("AT+CEREG=2", 2*time.Second)
	p.Exchange("AT+CREG=2", 2*time.Second)
	return nil
}

// ---- the store ----

type cellStore struct {
	mu      sync.Mutex
	path    string
	cfgPath string
	cfg     cellCfg
	obs     []cellObs
	fix     *cellFix
	current *cellObs
	lastErr string
	portOK  bool
	now     func() time.Time
	open    func(path string) (atPort, error)
	kick    chan struct{}
}

func newCellStore(path, cfgPath string) *cellStore {
	s := &cellStore{path: path, cfgPath: cfgPath, now: time.Now, open: openSerialAT, kick: make(chan struct{}, 1)}
	if b, err := os.ReadFile(cfgPath); err == nil {
		json.Unmarshal(b, &s.cfg)
	}
	if s.cfg.PeriodS == 0 {
		s.cfg.PeriodS = cellDefPeriodS
	}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &s.obs)
	}
	return s
}

func (s *cellStore) save() {
	b, _ := json.Marshal(s.obs)
	writeFileAtomic(s.path, b, 0o600)
}

func (s *cellStore) Cfg() cellCfg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *cellStore) Set(c cellCfg) error {
	c.Port = strings.TrimSpace(c.Port)
	if c.Enabled && c.Port == "" {
		return errors.New("give the modem's AT port (use Probe to find it)")
	}
	if c.Port != "" && (!strings.HasPrefix(c.Port, "/dev/") || strings.Contains(c.Port, "..") || len(c.Port) > 40) {
		return errors.New("the port must be a device under /dev")
	}
	if c.PeriodS == 0 {
		c.PeriodS = cellDefPeriodS
	}
	if c.PeriodS < cellMinPeriodS {
		c.PeriodS = cellMinPeriodS
	}
	if c.PeriodS > 3600 {
		c.PeriodS = 3600
	}
	s.mu.Lock()
	s.cfg = c
	s.lastErr = ""
	b, _ := json.MarshalIndent(c, "", " ")
	err := writeFileAtomic(s.cfgPath, b, 0o600)
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
	return err
}

// SetFix records where the box is now (RAM only).
func (s *cellStore) SetFix(lat, lon, alt, acc float64) error {
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0) {
		return errors.New("lat and lon must be real coordinates")
	}
	if acc < 0 || acc > 100000 {
		acc = 0
	}
	s.mu.Lock()
	s.fix = &cellFix{Lat: lat, Lon: lon, Alt: alt, Acc: acc, At: s.now()}
	s.mu.Unlock()
	return nil
}

func (s *cellStore) ClearFix() {
	s.mu.Lock()
	s.fix = nil
	s.mu.Unlock()
}

// record stores an observation, stamping it with the fix when fresh. To keep the file useful rather than full, a repeat of the same cell from the same spot (or
// with no fix) within 10 minutes replaces the previous row instead of adding one; a cell change or a move always adds.
func (s *cellStore) record(o cellObs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fix != nil && s.now().Sub(s.fix.At) <= cellFixFreshS*time.Second {
		o.Fix, o.Lat, o.Lon, o.Alt, o.Acc = true, s.fix.Lat, s.fix.Lon, s.fix.Alt, s.fix.Acc
	}
	cur := o
	s.current = &cur
	if n := len(s.obs); n > 0 {
		p := s.obs[n-1]
		same := p.key() == o.key() && p.Fix == o.Fix && o.T-p.T < 600
		if same && o.Fix {
			same = moved(p.Lat, p.Lon, o.Lat, o.Lon) < 25
		}
		if same {
			s.obs[n-1] = o
			s.save()
			return
		}
	}
	s.obs = append(s.obs, o)
	if len(s.obs) > cellMaxObs {
		s.obs = s.obs[len(s.obs)-cellMaxObs:]
	}
	s.save()
}

// moved: metres between two points, flat-earth, good enough to tell "still here" from "moved".
func moved(lat1, lon1, lat2, lon2 float64) float64 {
	dy := (lat2 - lat1) * 111320
	dx := (lon2 - lon1) * 111320 * cosDeg((lat1+lat2)/2)
	return sqrt(dx*dx + dy*dy)
}

func (s *cellStore) Clear() {
	s.mu.Lock()
	s.obs = nil
	s.current = nil
	s.save()
	s.mu.Unlock()
}

type towerView struct {
	Enabled    bool     `json:"enabled"`
	Port       string   `json:"port"`
	PeriodS    int      `json:"period_s"`
	PortOK     bool     `json:"port_ok"`
	LastErr    string   `json:"last_error,omitempty"`
	Current    *cellObs `json:"current,omitempty"`
	FixAgeS    int64    `json:"fix_age_s"` // -1 when there is no fix
	FixAcc     float64  `json:"fix_acc,omitempty"`
	Count      int      `json:"count"`
	WithFix    int      `json:"with_fix"`
	Cells      int      `json:"cells"` // distinct cells seen
	Oldest     int64    `json:"oldest,omitempty"`
	Candidates []string `json:"candidates"`
}

func (s *cellStore) View() towerView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := towerView{Enabled: s.cfg.Enabled, Port: s.cfg.Port, PeriodS: s.cfg.PeriodS, PortOK: s.portOK, LastErr: s.lastErr, Current: s.current, FixAgeS: -1, Candidates: cellPortCandidates}
	if s.fix != nil {
		v.FixAgeS = int64(s.now().Sub(s.fix.At).Seconds())
		v.FixAcc = s.fix.Acc
	}
	seen := map[string]bool{}
	for i, o := range s.obs {
		if i == 0 {
			v.Oldest = o.T
		}
		seen[o.key()] = true
		if o.Fix {
			v.WithFix++
		}
	}
	v.Count, v.Cells = len(s.obs), len(seen)
	return v
}

// Probe tries each candidate port (or the one given) with a bare AT and reports which answered.
func (s *cellStore) Probe(only string) map[string]string {
	ports := cellPortCandidates
	if only != "" {
		ports = []string{only}
	}
	out := map[string]string{}
	for _, p := range ports {
		if _, err := os.Stat(p); err != nil {
			out[p] = "not present"
			continue
		}
		port, err := s.open(p)
		if err != nil {
			out[p] = "could not open: " + err.Error()
			continue
		}
		if _, err := port.Exchange("AT", 2*time.Second); err != nil {
			out[p] = "no answer: " + err.Error()
		} else {
			out[p] = "answers OK"
		}
		port.Close()
	}
	return out
}

// Run polls the modem while enabled; the port is opened once and reopened after a failure.
func (s *cellStore) Run() {
	var port atPort
	for {
		cfg := s.Cfg()
		if !cfg.Enabled || cfg.Port == "" {
			if port != nil {
				port.Close()
				port = nil
			}
			s.mu.Lock()
			s.portOK = false
			s.mu.Unlock()
			<-s.kick
			continue
		}
		if port == nil {
			p, err := s.open(cfg.Port)
			if err == nil {
				err = setupPort(p)
				if err != nil {
					p.Close()
				}
			}
			s.mu.Lock()
			if err != nil {
				s.lastErr, s.portOK = err.Error(), false
			} else {
				s.lastErr, s.portOK = "", true
				port = p
			}
			s.mu.Unlock()
		}
		if port != nil {
			o, err := readCellObs(port, s.now())
			if err != nil {
				s.mu.Lock()
				s.lastErr = err.Error()
				s.mu.Unlock()
				if !strings.Contains(err.Error(), "registered") && !strings.Contains(err.Error(), "cell id") {
					port.Close()
					port = nil // a transport error: reopen next round
				}
			} else {
				s.record(o)
				s.mu.Lock()
				s.lastErr = ""
				s.mu.Unlock()
			}
		}
		select {
		case <-s.kick:
			if port != nil {
				port.Close()
				port = nil
			}
		case <-time.After(time.Duration(cfg.PeriodS) * time.Second):
		}
	}
}

// ---- WiGLE CSV ----

// wigleCSV renders the observations that carry a location in the WigleWifi-1.6 upload format: the pre-header names the app and device, then the column header,
// then one row per observation with the cell key in the MAC column, the operator as SSID, the technology as AuthMode and Type.
func wigleCSV(obs []cellObs, loc *time.Location) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "WigleWifi-1.6,appRelease=stone-of-heimdall %s,model=RC400L,release=%s,device=orbic,display=,board=mdm9607,brand=Orbic,star=Sol,body=3,subBody=0\n", version, version)
	b.WriteString("MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n")
	for _, o := range obs {
		if !o.Fix {
			continue
		}
		rssi := o.RSSI
		if o.RSRP != 0 {
			rssi = int(o.RSRP)
		}
		ssid := strings.NewReplacer(",", " ", "\"", "", "\n", " ").Replace(o.Op)
		fmt.Fprintf(&b, "%s,%s,%s,%s,%d,0,%d,%.6f,%.6f,%.1f,%.1f,,,%s\n", o.key(), ssid, o.Tech, time.Unix(o.T, 0).In(loc).Format("2006-01-02 15:04:05"), o.EARFCN, rssi, o.Lat, o.Lon, o.Alt, o.Acc, o.Tech)
	}
	return b.Bytes()
}

// ---- API ----

func handleCellAPI(w http.ResponseWriter, r *http.Request, path string) {
	if towers == nil {
		http.Error(w, "not found", 404)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	switch {
	case path == "towers" && r.Method == http.MethodGet:
		writeJSON(w, 200, towers.View())
	case path == "towers/set" && r.Method == http.MethodPost:
		var c cellCfg
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := towers.Set(c); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "towers/probe" && r.Method == http.MethodPost:
		var b struct{ Port string }
		json.NewDecoder(r.Body).Decode(&b)
		if b.Port != "" && !strings.HasPrefix(b.Port, "/dev/") {
			writeJSON(w, 400, map[string]string{"error": "the port must be a device under /dev"})
			return
		}
		writeJSON(w, 200, map[string]any{"ports": towers.Probe(b.Port)})
	case path == "towers/fix" && r.Method == http.MethodPost:
		var b struct{ Lat, Lon, Alt, Acc float64 }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := towers.SetFix(b.Lat, b.Lon, b.Alt, b.Acc); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "fix recorded"})
	case path == "towers/fix/clear" && r.Method == http.MethodPost:
		towers.ClearFix()
		writeJSON(w, 200, map[string]string{"status": "the fix was forgotten"})
	case path == "towers/clear" && r.Method == http.MethodPost:
		towers.Clear()
		writeJSON(w, 200, map[string]string{"status": "observations deleted"})
	case path == "towers/wigle.csv" && r.Method == http.MethodGet:
		if viaOnion(r) {
			writeJSON(w, 403, map[string]string{"error": "the tower log is not served through the onion door"})
			return
		}
		towers.mu.Lock()
		obs := append([]cellObs{}, towers.obs...)
		towers.mu.Unlock()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", "attachment; filename=\"stone-of-heimdall-"+time.Now().Format("20060102")+".csv\"")
		w.Write(wigleCSV(obs, schedLoc()))
	default:
		http.Error(w, "not found", 404)
	}
}

var towers *cellStore

func cosDeg(d float64) float64 { return math.Cos(d * math.Pi / 180) }
func sqrt(x float64) float64   { return math.Sqrt(x) }
