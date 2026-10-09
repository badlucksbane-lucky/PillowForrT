package main

// The original implementations of parseConntrack and scanProcs (before the allocation work), kept as oracles: the fast versions must give the same answers.

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// parseConntrack returns the original-direction flows of LAN hosts to non-LAN addresses (IPv4 tcp and udp).
func parseConntrackRef(s string) map[string]ctFlow {
	out := map[string]ctFlow{}
	_, lan, _ := net.ParseCIDR(lanCIDR)
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 8 || f[0] != "ipv4" || (f[2] != "tcp" && f[2] != "udp") {
			continue
		}
		kv := map[string]string{}
		for _, w := range f[4:] {
			if i := strings.IndexByte(w, '='); i > 0 {
				if _, dup := kv[w[:i]]; !dup {
					kv[w[:i]] = w[i+1:]
				}
			}
		}
		src, dst := net.ParseIP(kv["src"]), net.ParseIP(kv["dst"])
		port, _ := strconv.Atoi(kv["dport"])
		if src == nil || dst == nil || port == 0 || !lan.Contains(src) || lan.Contains(dst) || dst.IsLoopback() || dst.IsMulticast() || dst.Equal(net.IPv4bcast) {
			continue
		}
		out[f[2]+"|"+kv["src"]+"|"+kv["sport"]+"|"+kv["dst"]+"|"+kv["dport"]] = ctFlow{f[2], kv["src"], kv["dst"], port}
	}
	return out
}

func scanProcsRef(root string) (comms, stopped map[string]bool, lines []string) {
	comms, stopped = map[string]bool{}, map[string]bool{}
	es, _ := os.ReadDir(root)
	for _, e := range es {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(root, e.Name(), "comm")); err == nil {
			name := strings.TrimSpace(string(b))
			comms[name] = true
			if st, err := os.ReadFile(filepath.Join(root, e.Name(), "status")); err == nil && strings.Contains(string(st), "State:\tT") {
				stopped[name] = true
			}
		}
		if b, err := os.ReadFile(filepath.Join(root, e.Name(), "cmdline")); err == nil && len(b) > 0 {
			lines = append(lines, strings.ReplaceAll(string(b), "\x00", " "))
		}
	}
	return comms, stopped, lines
}

func TestConntrackFlowsMatchTheOriginal(t *testing.T) {
	edge := "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.40 dst=17.0.0.1 sport=50000 dport=443 src=17.0.0.1 dst=100.65.1.1 sport=443 dport=50000 mark=0 use=2\n" +
		"ipv6 10 tcp 6 100 ESTABLISHED src=fd00::1 dst=2001:db8::1 sport=50000 dport=443 src=2001:db8::1 dst=fd00::1 sport=443 dport=50000 use=2\n" +
		"ipv4 2 icmp 1 29 src=192.168.1.40 dst=8.8.8.8 type=8 code=0 id=1 src=8.8.8.8 dst=100.65.1.1 type=0 code=0 id=1 use=2\n" +
		"ipv4 2 udp 17 20 src=192.168.1.40 dst=127.0.0.1 sport=5000 dport=53 src=127.0.0.1 dst=192.168.1.40 sport=53 dport=5000 use=2\n" +
		"ipv4 2 udp 17 20 src=192.168.1.40 dst=224.0.0.251 sport=5353 dport=5353 src=224.0.0.251 dst=192.168.1.40 sport=5353 dport=5353 use=2\n" +
		"ipv4 2 udp 17 20 src=192.168.1.40 dst=255.255.255.255 sport=68 dport=67 src=255.255.255.255 dst=192.168.1.40 sport=67 dport=68 use=2\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.40 dst=5.6.7.8 sport=50001 dport=0 src=5.6.7.8 dst=100.65.1.1 sport=0 dport=50001 use=2\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=10.9.9.9 dst=5.6.7.8 sport=50001 dport=80 src=5.6.7.8 dst=10.9.9.9 sport=80 dport=50001 use=2\n" +
		"ipv4\t2\ttcp\t6\t100\tESTABLISHED\tsrc=192.168.1.41\tdst=9.9.9.9\tsport=1\tdport=2\tsrc=9.9.9.9\tdst=100.65.1.1\tsport=2\tdport=1\n" +
		"ipv4 2 tcp 6 100 src=192.168.1.42 dst=bogus sport=1 dport=2 src=1.1.1.1 dst=2.2.2.2 sport=2 dport=1\n" +
		"ipv4 2 tcp 6 src=192.168.1.43 dst=9.9.9.9\n" +
		"garbage\n\n   \n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.44 dst=9.9.9.9 sport=7 dport=8 src=9.9.9.9 dst=100.65.1.1 sport=8 dport=7 use=2" // no newline at the end
	for name, in := range map[string]string{"edge cases": edge, "3000 lines": conntrackDump(3000), "empty": "", "one blank": "\n"} {
		want, got := parseConntrackRef(in), parseConntrack(in)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: the new parser disagrees with the original (%d flows against %d)", name, len(got), len(want))
			for k, v := range want {
				if g, ok := got[k]; !ok || g != v {
					t.Logf("original has %s = %+v, new has %+v (%v)", k, v, g, ok)
					break
				}
			}
		}
	}
}

func TestConntrackFlowsDoNotKeepTheTableAlive(t *testing.T) {
	in := conntrackDump(50)
	es := conntrackFlows(in)
	if len(es) == 0 {
		t.Fatal("no flows")
	}
	lo := uintptr(unsafe.Pointer(unsafe.StringData(in)))
	hi := lo + uintptr(len(in))
	for _, e := range es {
		for name, sub := range map[string]string{"key": e.Key, "src": e.Flow.Src, "dst": e.Flow.Dst, "proto": e.Flow.Proto} {
			if p := uintptr(unsafe.Pointer(unsafe.StringData(sub))); p >= lo && p < hi {
				t.Errorf("%s %q points into the table's text", name, sub)
			}
		}
	}
}

func TestParseProcStat(t *testing.T) {
	for _, c := range []struct {
		in      string
		comm    string
		state   byte
		kthread bool
		ok      bool
	}{
		{"1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 1 2", "init", 'S', false, true},
		{"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0", "kthreadd", 'S', true, true},
		{"14 (upgrade) T 1 1 1 0 -1 4194560 0 0", "upgrade", 'T', false, true},
		{"77 (a) b (c d)) R 1 1 1 0 -1 4194560 0 0", "a) b (c d)", 'R', false, true}, // a name may hold parentheses and spaces
		{"5 (x) S 1", "x", 'S', false, true},                                         // cut short: still the name and state
		{"", "", 0, false, false},
		{"5 x S 1 1 1", "", 0, false, false},
		{"5 (x)", "", 0, false, false},
	} {
		comm, state, kt, ok := parseProcStat([]byte(c.in))
		if ok != c.ok || string(comm) != c.comm || state != c.state || kt != c.kthread {
			t.Errorf("%q: got (%q, %c, %v, %v)", c.in, comm, state, kt, ok)
		}
	}
}

// procSnapshot copies the real /proc into a directory, in the shape both scanners read (comm, status, stat, cmdline), so that the original and the new scan see exactly the same thing:
// the real /proc changes between any two scans. comm and status are derived from the stat file in the same snapshot, so they cannot disagree with it.
func procSnapshot(t *testing.T) string {
	dir := t.TempDir()
	es, _ := os.ReadDir("/proc")
	for _, e := range es {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		st, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		i, j := strings.IndexByte(string(st), '('), strings.LastIndexByte(string(st), ')')
		if err != nil || i < 0 || j < i || j+2 >= len(st) {
			continue
		}
		d := filepath.Join(dir, e.Name())
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "stat"), st, 0o644)
		os.WriteFile(filepath.Join(d, "comm"), []byte(string(st[i+1:j])+"\n"), 0o644)
		os.WriteFile(filepath.Join(d, "status"), []byte("Name:\t"+string(st[i+1:j])+"\nState:\t"+string(st[j+2:j+3])+" (x)\n"), 0o644)
		if cl, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil {
			os.WriteFile(filepath.Join(d, "cmdline"), cl, 0o644)
		}
	}
	return dir
}

func TestScanProcsMatchesTheOriginalOnASnapshotOfTheRealProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("needs /proc")
	}
	dir := procSnapshot(t)
	c1, s1, l1 := scanProcsRef(dir)
	c2, s2, l2 := scanProcs(dir)
	if len(c1) < 20 {
		t.Fatalf("only %d command names in the snapshot", len(c1))
	}
	if !reflect.DeepEqual(c1, c2) || !reflect.DeepEqual(s1, s2) {
		t.Errorf("command names or stopped set differ (%d against %d names, %d against %d stopped)", len(c1), len(c2), len(s1), len(s2))
	}
	sort.Strings(l1)
	sort.Strings(l2)
	if !reflect.DeepEqual(l1, l2) {
		t.Errorf("command lines differ (original %d, new %d)", len(l1), len(l2))
		for i := 0; i < len(l1) && i < len(l2); i++ {
			if l1[i] != l2[i] {
				t.Logf("first difference:\n original %.120q\n new      %.120q", l1[i], l2[i])
				break
			}
		}
	}
}
