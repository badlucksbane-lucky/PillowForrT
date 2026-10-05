package main

// The DNS filter: which names are blocked. A catalog of published lists (defaultLists), each switched on or off, plus the owner's own wildcard rules (filtrules.go).
// Lists differ in how they are published: "wildcard" lists cover an entry's subdomains too (suffix match), "exact" lists do not. Every downloaded list stays in memory
// as sorted 64-bit hashes (8 bytes a name; hashset.go), so enabling or disabling one is instant, with no reload and no DNS stall. All lists together are held to
// maxTotalEntries (about 19 MB, 20 MB is acceptable); a download that would exceed it is refused and the old copy kept. Downloads are streamed straight
// into hashes and the compiled file, so a big list never exists as a slice of strings.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type listSpec struct {
	Name     string
	URL      string
	Format   string // "domains" | "hosts"
	Wildcard bool
	Category string
	Desc     string
	Min      int  // fewer entries than this is a broken download (0 = 10000)
	Default  bool // enabled on a fresh install
}

const maxListEntries = 1_000_000  // one list
const maxTotalEntries = 2_400_000 // all lists together: about 19 MB of hashes

var defaultLists = []listSpec{
	{"oisd", "https://small.oisd.nl/domainswild2", "domains", true, "Ads and trackers", "OISD small: a short, low-breakage list", 0, true},
	{"stevenblack", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts", false, "Ads and trackers", "StevenBlack unified hosts", 0, true},
	{"hagezi-pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt", "domains", true, "Ads and trackers", "HaGeZi Multi PRO: ads, trackers, malware (a bigger broom)", 0, false},
	{"peterlowe", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "hosts", false, "Ads and trackers", "Peter Lowe's ad server list", 1000, false},
	{"hagezi-tif", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt", "domains", true, "Malware and phishing", "HaGeZi threat intelligence feeds (medium)", 0, false},
	{"phishing-army", "https://phishing.army/download/phishing_army_blocklist.txt", "domains", true, "Malware and phishing", "Phishing Army: extended phishing domains", 0, false},
	{"urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", "hosts", true, "Malware and phishing", "abuse.ch URLhaus: hosts serving malware right now", 100, false},
	{"nocoin", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "hosts", true, "Telemetry and miners", "Browser crypto-miners", 100, false},
	{"smarttv", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", "domains", true, "Telemetry and miners", "Smart TV tracking and ads", 100, false},
	{"windows-spy", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "hosts", true, "Telemetry and miners", "Windows telemetry (WindowsSpyBlocker)", 100, false},
	{"hagezi-doh", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt", "domains", true, "Bypass attempts", "Public DoH/DoT servers: stops browsers choosing their own DNS", 1000, false},
	{"hagezi-nsfw", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt", "domains", true, "Content", "Adult content", 0, false},
	{"hagezi-gambling", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt", "domains", true, "Content", "Gambling", 0, false},
	{"hagezi-social", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/social-onlydomains.txt", "domains", true, "Content", "Social networks", 100, false},
}

// legacyModes are the four fixed modes of the first version; they still load (from old state and snapshots) and are converted to "on" plus a set of enabled lists.
var legacyModes = map[string][]string{"oisd": {"oisd"}, "stevenblack": {"stevenblack"}, "both": {"oisd", "stevenblack"}}

// Global mode: "off" or "on" (the enabled lists apply). Per-device mode: "" or "default" (the global choice), "off", "strict" (every downloaded list, enabled or not), or a legacy name.
func validGlobalMode(m string) bool { _, leg := legacyModes[m]; return m == "off" || m == "on" || leg }
func validDeviceMode(m string) bool {
	_, leg := legacyModes[m]
	return m == "" || m == "default" || m == "off" || m == "strict" || leg
}

func listKnown(name string) (listSpec, bool) {
	for _, sp := range defaultLists {
		if sp.Name == name {
			return sp, true
		}
	}
	return listSpec{}, false
}

type listData struct {
	Name    string    `json:"name"`
	Wild    bool      `json:"wildcard"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated"`
	ETag    string    `json:"-"`
	LastMod string    `json:"-"`
	Err     string    `json:"error,omitempty"`
	Cat     string    `json:"category,omitempty"`
	Desc    string    `json:"desc,omitempty"`
	On      bool      `json:"enabled"`
	set     hashSet
}

type Filter struct {
	dir        string
	mu         sync.RWMutex
	lists      map[string]*listData
	mode       string
	allow      map[string]struct{}
	devMode    map[string]string // device address -> mode override (absent = the default mode)
	enabled    map[string]bool
	custom     *customRules
	allowGlob  []string
	pauseUntil time.Time
}

func NewFilter(dir string) *Filter {
	en := map[string]bool{}
	for _, sp := range defaultLists {
		en[sp.Name] = sp.Default
	}
	return &Filter{dir: dir, lists: map[string]*listData{}, mode: "on", allow: map[string]struct{}{}, devMode: map[string]string{}, enabled: en, custom: newCustomRules(dir)}
}

var skipNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true,
}

// validHost: a plausible blockable name (letters, digits, dot, hyphen, underscore; has a dot; not an IP literal).
func validHost(n string) bool {
	if len(n) < 3 || len(n) > 253 || strings.IndexByte(n, '.') < 0 || skipNames[n] || net.ParseIP(n) != nil {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return n[0] != '.' && n[len(n)-1] != '.'
}

// listLine reduces one line of a published list to the names it blocks (none for comments, blanks and rules it cannot use).
func listLine(line, format string) []string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if format == "hosts" {
		f := strings.Fields(line)
		if len(f) < 2 || net.ParseIP(f[0]) == nil {
			return nil
		}
		var out []string
		for _, n := range f[1:] {
			if n = strings.ToLower(n); validHost(n) {
				out = append(out, n)
			}
		}
		return out
	}
	n := strings.ToLower(line)
	n = strings.TrimPrefix(strings.TrimPrefix(n, "||"), "*.")
	n = strings.TrimSuffix(n, "^")
	if validHost(n) {
		return []string{n}
	}
	return nil
}

// parseList reads a whole list into sorted unique names (used by tests and tools; the filter itself streams, see compileStream).
func parseList(r io.Reader, format string) ([]string, error) {
	var names []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		names = append(names, listLine(sc.Text(), format)...)
	}
	sort.Strings(names)
	out := names[:0]
	for i, n := range names {
		if i == 0 || n != names[i-1] {
			out = append(out, n)
		}
	}
	return out, sc.Err()
}

// compileStream reads a published list line by line, hashing every name into the returned set and writing the clean names (one per line) to outPath, so the list never
// sits in memory as strings. It stops with an error beyond max entries.
func compileStream(r io.Reader, format, outPath string, max int) (hashSet, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(f, 1<<16)
	var h hashSet
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		for _, n := range listLine(sc.Text(), format) {
			if len(h) >= max {
				f.Close()
				os.Remove(outPath)
				return nil, errors.New("more than the allowed entries for one list")
			}
			h = append(h, hashName(n))
			w.WriteString(n)
			w.WriteByte('\n')
		}
	}
	if err := sc.Err(); err != nil {
		f.Close()
		os.Remove(outPath)
		return nil, err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(outPath)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return sealHashSet(h), nil
}

// loadCompiled reads a compiled list file back into a hash set.
func loadCompiled(path string, max int) (hashSet, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var h hashSet
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if n := strings.TrimSpace(sc.Text()); n != "" && len(h) < max {
			h = append(h, hashName(n))
		}
	}
	return sealHashSet(h), sc.Err()
}

func writeList(path string, names []string) error { // names are sorted and unique, as parseList returns them
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<16)
	for _, n := range names {
		w.WriteString(n)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type filterState struct {
	Mode    string                       `json:"mode"`
	Enabled []string                     `json:"enabled,omitempty"`
	Devs    map[string]string            `json:"devices,omitempty"` // per-device mode overrides
	Lists   map[string]map[string]string `json:"lists,omitempty"`   // name -> {etag, lastmod, updated}
}

func (f *Filter) statePath() string { return filepath.Join(f.dir, "state.json") }
func (f *Filter) allowPath() string { return filepath.Join(f.dir, "allow.txt") }
func (f *Filter) listPath(name string) string {
	return filepath.Join(f.dir, name+".list")
}

func (f *Filter) saveState() {
	st := filterState{Mode: f.mode, Devs: f.devMode, Lists: map[string]map[string]string{}}
	for _, sp := range defaultLists {
		if f.enabled[sp.Name] {
			st.Enabled = append(st.Enabled, sp.Name)
		}
	}
	if st.Enabled == nil {
		st.Enabled = []string{} // "none enabled" must not read back as "never set"
	}
	for n, l := range f.lists {
		st.Lists[n] = map[string]string{"etag": l.ETag, "lastmod": l.LastMod, "updated": l.Updated.Format(time.RFC3339)}
	}
	b, _ := json.Marshal(st)
	tmp := f.statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, f.statePath())
	}
}

// Load reads the saved mode, the allow-list and every compiled list that exists on disk. Missing pieces are not errors.
func (f *Filter) Load() {
	os.MkdirAll(f.dir, 0o755)
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, err := os.ReadFile(f.statePath()); err == nil {
		var st filterState
		if json.Unmarshal(b, &st) == nil {
			if validGlobalMode(st.Mode) {
				if leg, ok := legacyModes[st.Mode]; ok { // first-version state: "both" becomes on + those two lists
					f.mode = "on"
					f.enabled = map[string]bool{}
					for _, n := range leg {
						f.enabled[n] = true
					}
				} else {
					f.mode = st.Mode
				}
			}
			if st.Enabled != nil && legacyModes[st.Mode] == nil {
				f.enabled = map[string]bool{}
				for _, n := range st.Enabled {
					if _, ok := listKnown(n); ok {
						f.enabled[n] = true
					}
				}
			}
			for ip, m := range st.Devs {
				if validDeviceMode(m) && m != "" && net.ParseIP(ip) != nil && len(f.devMode) < 64 {
					f.devMode[ip] = m
				}
			}
			for n, m := range st.Lists {
				if l := f.lists[n]; l != nil {
					l.ETag, l.LastMod = m["etag"], m["lastmod"]
				} else {
					f.lists[n] = &listData{Name: n, ETag: m["etag"], LastMod: m["lastmod"]}
				}
				if t, err := time.Parse(time.RFC3339, m["updated"]); err == nil {
					f.lists[n].Updated = t
				}
			}
		}
	}
	total := 0
	for _, sp := range defaultLists {
		if _, err := os.Stat(f.listPath(sp.Name)); err != nil {
			continue
		}
		set, err := loadCompiled(f.listPath(sp.Name), maxListEntries)
		l := f.lists[sp.Name]
		if l == nil {
			l = &listData{Name: sp.Name}
			f.lists[sp.Name] = l
		}
		if err != nil || len(set) == 0 {
			continue
		}
		if total+len(set) > maxTotalEntries {
			l.Err = "not loaded: the lists together would pass the memory budget"
			continue
		}
		total += len(set)
		l.Wild, l.set, l.Entries = sp.Wildcard, set, len(set)
		if l.Updated.IsZero() {
			if fi, err := os.Stat(f.listPath(sp.Name)); err == nil {
				l.Updated = fi.ModTime()
			}
		}
	}
	f.custom = newCustomRules(f.dir)
	if b, err := os.ReadFile(f.allowPath()); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if ln = strings.ToLower(strings.TrimSpace(ln)); ln != "" && !strings.HasPrefix(ln, "#") {
				f.allow[ln] = struct{}{}
			}
		}
		f.rebuildAllowGlobs()
	}
}

func (f *Filter) rebuildAllowGlobs() {
	f.allowGlob = f.allowGlob[:0]
	for n := range f.allow {
		if strings.Contains(n, "*") {
			f.allowGlob = append(f.allowGlob, n)
		}
	}
}

// setListSet publishes a freshly compiled list (already written to disk by the caller). It refuses a list that would push the total past the memory budget.
func (f *Filter) setListSet(sp listSpec, set hashSet, etag, lastmod string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := len(set)
	for n, l := range f.lists {
		if n != sp.Name {
			total += l.Entries
		}
	}
	if total > maxTotalEntries {
		return fmt.Errorf("would pass the memory budget (%d names in all, at most %d)", total, maxTotalEntries)
	}
	l := f.lists[sp.Name]
	if l == nil {
		l = &listData{Name: sp.Name}
		f.lists[sp.Name] = l
	}
	l.Wild, l.set, l.Entries, l.Updated, l.ETag, l.LastMod, l.Err = sp.Wildcard, set, len(set), time.Now(), etag, lastmod, ""
	f.saveState()
	return nil
}

// touchList records that the list was checked and is current (HTTP 304).
func (f *Filter) touchList(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.lists[name]; l != nil {
		l.Updated, l.Err = time.Now(), ""
		f.saveState()
	}
}

func (f *Filter) setListErr(name, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.lists[name]
	if l == nil {
		l = &listData{Name: name}
		f.lists[name] = l
	}
	l.Err = msg
}

func (f *Filter) Mode() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mode
}

func (f *Filter) SetMode(m string) error {
	if !validGlobalMode(m) {
		return errors.New("mode must be off or on")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if leg, ok := legacyModes[m]; ok { // an old client asking for "both": the same thing, spelled as lists
		f.enabled = map[string]bool{}
		for _, n := range leg {
			f.enabled[n] = true
		}
		m = "on"
	}
	f.mode = m
	f.saveState()
	return nil
}

// SetListEnabled switches one list on or off for the default mode.
func (f *Filter) SetListEnabled(name string, on bool) error {
	if _, ok := listKnown(name); !ok {
		return errors.New("unknown list")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled[name] = on
	f.saveState()
	return nil
}

// SetDeviceMode gives one device its own mode; "" (or "default") puts it back on the default.
func (f *Filter) SetDeviceMode(ip, mode string) error {
	if net.ParseIP(ip) == nil {
		return errors.New("not a device address")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if mode == "" || mode == "default" {
		delete(f.devMode, ip)
	} else {
		if !validDeviceMode(mode) {
			return errors.New("mode must be default, off or strict")
		}
		if _, had := f.devMode[ip]; !had && len(f.devMode) >= 64 {
			return errors.New("too many device overrides")
		}
		f.devMode[ip] = mode
	}
	f.saveState()
	return nil
}

func (f *Filter) DeviceModes() map[string]string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]string, len(f.devMode))
	for k, v := range f.devMode {
		out[k] = v
	}
	return out
}

func (f *Filter) Pause(d time.Duration) {
	f.mu.Lock()
	f.pauseUntil = time.Now().Add(d)
	f.mu.Unlock()
}

func (f *Filter) Resume() { f.Pause(0) }

func (f *Filter) PausedUntil() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if time.Now().Before(f.pauseUntil) {
		return f.pauseUntil
	}
	return time.Time{}
}

// suffixHit reports whether name or any parent with at least one dot (never a bare TLD) is in the set that has describes.
func suffixHit(has func(string) bool, name string) bool {
	s := name
	for {
		if has(s) {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 || strings.IndexByte(s[i+1:], '.') < 0 {
			return false
		}
		s = s[i+1:]
	}
}

// Match says whether name is blocked right now, and by which list. The allow-list wins (it covers subdomains), a pause or "off" disables the filter.
func (f *Filter) Match(name string, now time.Time) (bool, string) { return f.MatchFor("", name, now) }

// decision is what the filter did with a name and why (the "why was this blocked?" answer).
type decision struct {
	Name     string `json:"name"`
	Client   string `json:"client,omitempty"`
	Result   string `json:"result"` // blocked | allowed | not listed | filter off | paused
	By       string `json:"by,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Category string `json:"category,omitempty"`
}

// listsFor returns the names of the lists that apply for a mode. Caller holds f.mu.
func (f *Filter) listsFor(mode string) []string {
	var out []string
	switch {
	case mode == "off":
	case mode == "strict":
		for _, sp := range defaultLists {
			if l := f.lists[sp.Name]; l != nil && l.set != nil {
				out = append(out, sp.Name)
			}
		}
	case legacyModes[mode] != nil:
		out = legacyModes[mode]
	default: // "on" / "default"
		for _, sp := range defaultLists {
			if f.enabled[sp.Name] {
				out = append(out, sp.Name)
			}
		}
	}
	return out
}

func (f *Filter) decide(client, name string, now time.Time) decision {
	d := decision{Name: name, Client: client, Result: "not listed"}
	mode := f.mode
	if m, ok := f.devMode[client]; ok {
		mode = m
	}
	if mode == "off" {
		d.Result = "filter off"
		return d
	}
	if now.Before(f.pauseUntil) {
		d.Result = "paused"
		return d
	}
	if len(f.allow) > 0 {
		if suffixHit(func(s string) bool { _, ok := f.allow[s]; return ok }, name) {
			d.Result, d.By = "allowed", "your always-allow list"
			return d
		}
		for _, g := range f.allowGlob {
			if patternMatch(g, name) {
				d.Result, d.By, d.Detail = "allowed", "your always-allow list", g
				return d
			}
		}
	}
	if f.custom != nil && !strings.HasPrefix(client, "127.") && client != "::1" {
		if p, ok := f.custom.Match(client, name, now); ok {
			d.Result, d.By, d.Detail, d.Category = "blocked", "custom", p, "Your rules"
			return d
		}
	}
	for _, ln := range f.listsFor(mode) {
		l := f.lists[ln]
		if l == nil || l.set == nil {
			continue
		}
		hit := false
		if l.Wild {
			hit = suffixHit(l.set.has, name)
		} else {
			hit = l.set.has(name)
		}
		if hit {
			sp, _ := listKnown(ln)
			d.Result, d.By, d.Category = "blocked", ln, sp.Category
			return d
		}
	}
	return d
}

// MatchFor is Match for a particular device: its own mode, when it has one, replaces the default (a global pause still switches everything off).
func (f *Filter) MatchFor(client, name string, now time.Time) (bool, string) {
	f.mu.RLock()
	d := f.decide(client, name, now)
	f.mu.RUnlock()
	return d.Result == "blocked", d.By
}

// Explain says what would happen to a lookup of name from client, and why.
func (f *Filter) Explain(client, name string, now time.Time) decision {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.decide(client, name, now)
}

func (f *Filter) AllowList() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.allow))
	for n := range f.allow {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (f *Filter) saveAllow() {
	names := make([]string, 0, len(f.allow))
	for n := range f.allow {
		names = append(names, n)
	}
	sort.Strings(names)
	tmp := f.allowPath() + ".tmp"
	if os.WriteFile(tmp, []byte(strings.Join(names, "\n")+"\n"), 0o644) == nil {
		os.Rename(tmp, f.allowPath())
	}
}

func (f *Filter) AllowAdd(name string) error {
	name, err := normalizePattern(name)
	if err != nil {
		return err
	}
	if !strings.Contains(name, "*") && !validHost(name) {
		return errors.New("not a valid domain name")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allow[name] = struct{}{}
	f.rebuildAllowGlobs()
	f.saveAllow()
	return nil
}

func (f *Filter) AllowRemove(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.allow, name)
	f.rebuildAllowGlobs()
	f.saveAllow()
}

func (f *Filter) Lists() []listData {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]listData, 0, len(defaultLists))
	for _, sp := range defaultLists {
		if l := f.lists[sp.Name]; l != nil {
			c := *l
			c.set = nil
			c.Wild, c.Cat, c.Desc, c.On = sp.Wildcard, sp.Category, sp.Desc, f.enabled[sp.Name]
			out = append(out, c)
		} else {
			out = append(out, listData{Name: sp.Name, Wild: sp.Wildcard, Cat: sp.Category, Desc: sp.Desc, On: f.enabled[sp.Name]})
		}
	}
	return out
}

// wanted: a list is kept fresh when it is switched on or already downloaded (so a disabled list that was used before still gets its daily check).
func (f *Filter) wanted(name string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	l := f.lists[name]
	return f.enabled[name] || (l != nil && l.Entries > 0)
}

// EnabledLists, SetEnabledLists, CustomRules and ReplaceCustom are for snapshots (backup and restore).
func (f *Filter) EnabledLists() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []string
	for _, sp := range defaultLists {
		if f.enabled[sp.Name] {
			out = append(out, sp.Name)
		}
	}
	return out
}

func (f *Filter) SetEnabledLists(names []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = map[string]bool{}
	for _, n := range names {
		if _, ok := listKnown(n); ok {
			f.enabled[n] = true
		}
	}
	f.saveState()
}

func (f *Filter) CustomRules() []customRule { return f.custom.List(time.Now()) }

func (f *Filter) ReplaceCustom(rs []customRule) {
	f.custom.mu.Lock()
	f.custom.rules = nil
	for _, r := range rs {
		if p, err := normalizePattern(r.Pattern); err == nil && len(f.custom.rules) < maxCustomRules {
			r.Pattern = p
			f.custom.rules = append(f.custom.rules, r)
		}
	}
	f.custom.saveLocked()
	f.custom.mu.Unlock()
}

func (f *Filter) hasList(name string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	l := f.lists[name]
	return l != nil && l.Entries > 0
}

// TotalEntries is the number of names held across all lists (against maxTotalEntries).
func (f *Filter) TotalEntries() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n := 0
	for _, l := range f.lists {
		n += l.Entries
	}
	return n
}
