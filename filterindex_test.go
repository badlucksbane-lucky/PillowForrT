package main

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

// refFilter is the filter as it was before the lists were merged: one sorted hash set a list, searched list by list in catalog order, the first list with a hit named. It is the
// oracle the merged index is checked against.
type refFilter struct {
	sets map[string]hashSet
}

func (r *refFilter) match(f *Filter, mode, name string) (bool, string) {
	var order []string
	switch {
	case mode == "off":
	case mode == "strict":
		for _, sp := range defaultLists {
			if r.sets[sp.Name] != nil {
				order = append(order, sp.Name)
			}
		}
	case legacyModes[mode] != nil:
		order = legacyModes[mode]
	default:
		for _, sp := range defaultLists {
			if f.enabled[sp.Name] {
				order = append(order, sp.Name)
			}
		}
	}
	for _, ln := range order {
		set := r.sets[ln]
		if set == nil {
			continue
		}
		sp, _ := listKnown(ln)
		hit := false
		if sp.Wildcard {
			hit = suffixHit(set.has, name)
		} else {
			hit = set.has(name)
		}
		if hit {
			return true, ln
		}
	}
	return false, ""
}

// randomLists makes overlapping lists: a pool of names, each list taking a random part of it.
func randomLists(rng *rand.Rand) (map[string][]string, []string) {
	var pool []string
	for i := 0; i < 600; i++ {
		switch rng.Intn(3) {
		case 0:
			pool = append(pool, fmt.Sprintf("d%d.example.com", i))
		case 1:
			pool = append(pool, fmt.Sprintf("t%d.cdn%d.example.net", i, i%7))
		default:
			pool = append(pool, fmt.Sprintf("x%d.example.co.uk", i))
		}
	}
	lists := map[string][]string{}
	for _, sp := range defaultLists {
		var names []string
		for _, n := range pool {
			if rng.Intn(5) == 0 {
				names = append(names, n)
			}
		}
		lists[sp.Name] = names
	}
	return lists, pool
}

func queriesFrom(rng *rand.Rand, pool []string, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		base := pool[rng.Intn(len(pool))]
		switch rng.Intn(6) {
		case 0:
			out = append(out, base)
		case 1:
			out = append(out, "www."+base)
		case 2:
			out = append(out, fmt.Sprintf("a%d.b%d.%s", rng.Intn(9), rng.Intn(9), base))
		case 3: // the parent: listed only where a wildcard list has the child's parent
			if i := indexByte(base, '.'); i >= 0 {
				out = append(out, base[i+1:])
			}
		case 4:
			out = append(out, fmt.Sprintf("unrelated%d.example.org", rng.Intn(1000)))
		default:
			out = append(out, "com", "example.com", "co.uk", "net")
		}
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func compareFilters(t *testing.T, label string, f *Filter, ref *refFilter, rng *rand.Rand, pool []string) {
	t.Helper()
	now := time.Now()
	names := queriesFrom(rng, pool, 1500)
	enabledSets := []map[string]bool{{}, {"oisd": true}, {"oisd": true, "stevenblack": true}, {}}
	for _, sp := range defaultLists {
		if rng.Intn(2) == 0 {
			enabledSets[3][sp.Name] = true
		}
		enabledSets[0][sp.Name] = true
	}
	checked, blocked := 0, 0
	for _, en := range enabledSets {
		f.mu.Lock()
		f.enabled = en
		f.recountEnabled()
		f.mu.Unlock()
		for _, dev := range []string{"", "off", "strict", "oisd", "stevenblack", "both"} {
			client := "192.168.1.77"
			f.mu.Lock()
			delete(f.devMode, client)
			if dev != "" {
				f.devMode[client] = dev
			}
			f.mu.Unlock()
			mode := "on"
			if dev != "" {
				mode = dev
			}
			for _, name := range names {
				wantB, wantBy := ref.match(f, mode, name)
				gotB, gotBy := f.MatchFor(client, name, now)
				checked++
				if wantB {
					blocked++
				}
				if wantB != gotB || (wantB && wantBy != gotBy) {
					t.Fatalf("%s: mode %q, %d enabled lists, %q: merged says (%v, %q), the per-list search says (%v, %q)", label, mode, len(en), name, gotB, gotBy, wantB, wantBy)
				}
			}
		}
	}
	if blocked < checked/20 || blocked > checked*19/20 {
		t.Fatalf("%s: the test is not testing anything: %d of %d blocked", label, blocked, checked)
	}
}

func TestMergedIndexMatchesPerListSearch(t *testing.T) {
	for _, div := range []int{8, 0} { // fold the overlay into the table at an eighth of its size (the default), or never
		t.Run(fmt.Sprintf("overlayDiv=%d", div), func(t *testing.T) {
			old := overlayDiv
			overlayDiv = div
			defer func() { overlayDiv = old }()
			mergedIndexMatchesPerListSearch(t, div == 0)
		})
	}
}

func mergedIndexMatchesPerListSearch(t *testing.T, neverFold bool) {
	rng := rand.New(rand.NewSource(7))
	lists, pool := randomLists(rng)
	ref := &refFilter{sets: map[string]hashSet{}}
	dir := t.TempDir()

	// built the way the updater does it, one list at a time
	f := NewFilter(dir)
	for _, sp := range defaultLists {
		ref.sets[sp.Name] = newHashSet(lists[sp.Name])
		testSetList(f, sp, lists[sp.Name], "", "")
	}
	compareFilters(t, "published one by one", f, ref, rng, pool)

	// built the way start-up does it: from the compiled files on disk
	for _, sp := range defaultLists {
		writeList(filepath.Join(dir, sp.Name+".list"), lists[sp.Name])
	}
	g := NewFilter(dir)
	g.Load()
	compareFilters(t, "loaded from disk", g, ref, rng, pool)

	// lists are replaced, one after another (the daily update), with names the table has not seen and with names it has
	fresh := []string{"fresh1.example.com", "fresh2.example.com", "sub.fresh3.example.net"}
	for round, name := range []string{"hagezi-pro", "oisd", "hagezi-gambling", "oisd"} {
		repl := append([]string{pool[round], pool[round+10], pool[round+20]}, fresh[:round%3+1]...)
		ref.sets[name] = newHashSet(repl)
		testSetList(g, defaultLists[listBit[name]], repl, "", "")
		compareFilters(t, fmt.Sprintf("after replacing %s (round %d)", name, round), g, ref, rng, append(append([]string{}, pool...), fresh...))
	}
	if neverFold && (g.index.over == nil || len(g.index.over.keys) == 0) {
		t.Error("the overlay was never used: the test does not test the overlay")
	}

	// a list is emptied
	g.mu.Lock()
	g.index = g.index.withList(listBit["oisd"], nil)
	g.mu.Unlock()
	ref.sets["oisd"] = nil
	compareFilters(t, "after emptying a list", g, ref, rng, append(append([]string{}, pool...), fresh...))
}

func TestIndexLookupIsExactAndBucketsAreSound(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	var parts []listPart
	want := map[uint64]uint16{} // by key: the hash with its low 4 bits cleared
	for bit := 0; bit < 5; bit++ {
		var h hashSet
		for i := 0; i < 5000; i++ {
			v := rng.Uint64()
			if i%3 == 0 && len(want) > 0 { // share keys between lists
				for k := range want {
					v = k | uint64(rng.Intn(16)) // and differ only in the bits that are not part of the key
					break
				}
			}
			h = append(h, v)
		}
		h = sealHashSet(h)
		for _, v := range h {
			want[v&keyMask] |= 1 << bit
		}
		parts = append(parts, listPart{bit, h})
	}
	check := func(label string, ix *listIndex) {
		if len(ix.keys) != len(want) {
			t.Fatalf("%s: %d keys, want %d", label, len(ix.keys), len(want))
		}
		for i := 1; i < len(ix.keys); i++ {
			if ix.keys[i] <= ix.keys[i-1] {
				t.Fatalf("%s: keys not sorted and unique at %d", label, i)
			}
		}
		for k, m := range want {
			if got := ix.lookup(k | 7); got != m { // any low bits find the key
				t.Fatalf("%s: key %x: mask %b, want %b", label, k, got, m)
			}
		}
		for i := 0; i < 20000; i++ {
			if k := rng.Uint64(); want[k&keyMask] == 0 && ix.lookup(k) != 0 {
				t.Fatalf("%s: absent key %x found", label, k)
			}
		}
		if int(ix.starts[len(ix.starts)-1]) != len(ix.keys) || ix.starts[0] != 0 {
			t.Errorf("%s: bucket table does not cover the keys", label)
		}
	}
	check("merged from sorted sets", (*listIndex)(nil).withLists(parts))

	var recs []uint64 // the same lists, the way start-up builds them
	for _, p := range parts {
		for _, v := range p.set {
			recs = append(recs, tagRecord(v, p.bit))
		}
	}
	rng.Shuffle(len(recs), func(i, j int) { recs[i], recs[j] = recs[j], recs[i] })
	ix := indexFromRecords(recs)
	check("built in place from tagged records", ix)
	counts := ix.listCounts()
	for bit, p := range parts {
		distinct := map[uint64]bool{}
		for _, v := range p.set {
			distinct[v&keyMask] = true
		}
		if counts[bit] != len(distinct) {
			t.Errorf("list %d: %d names counted, %d expected", bit, counts[bit], len(distinct))
		}
	}
	// replacing one list, and merging two indexes, keep the others
	only := (*listIndex)(nil).withLists(parts[:2])
	both := mergeIndexes(only, (*listIndex)(nil).withLists(parts[2:]))
	check("two indexes merged", both)
	if (*listIndex)(nil).lookup(1) != 0 || (&listIndex{}).lookup(1) != 0 || (*listIndex)(nil).match("a.example.com", 0xffff) != 0 || indexFromRecords(nil).lookup(5) != 0 {
		t.Error("an empty index must find nothing")
	}
}

func TestListCatalogFitsTheMask(t *testing.T) {
	if len(defaultLists) > 16 {
		t.Fatal("more lists than mask bits")
	}
	if legacyMask["both"] != 1<<listBit["oisd"]|1<<listBit["stevenblack"] {
		t.Errorf("legacy mask %b", legacyMask["both"])
	}
	// the first list in catalog order must be the lowest bit: the merged lookup names the lowest bit
	for i, sp := range defaultLists {
		if listBit[sp.Name] != i {
			t.Errorf("%s: bit %d, position %d", sp.Name, listBit[sp.Name], i)
		}
	}
}
