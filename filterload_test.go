package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFilterAnswersBeforeListsAreRead(t *testing.T) {
	dir := t.TempDir()
	if err := writeList(filepath.Join(dir, "oisd.list"), []string{"ads.example.com", "wild.example.net"}); err != nil {
		t.Fatal(err)
	}
	if err := writeList(filepath.Join(dir, "stevenblack.list"), []string{"track.example.org"}); err != nil {
		t.Fatal(err)
	}
	f := NewFilter(dir)
	f.LoadBase() // the filter answers now, with no list in it yet
	now := time.Now()
	if b, _ := f.Match("ads.example.com", now); b {
		t.Error("nothing is blocked before the lists are read: the filter fails open for those seconds")
	}
	if f.WaitLoaded(10 * time.Millisecond) {
		t.Error("not loaded yet")
	}
	f.LoadLists()
	if !f.WaitLoaded(time.Second) {
		t.Error("loaded: WaitLoaded must return at once")
	}
	for _, n := range []string{"ads.example.com", "sub.wild.example.net", "track.example.org"} {
		if b, _ := f.Match(n, now); !b {
			t.Errorf("%s not blocked after the lists are read", n)
		}
	}
	if f.TotalEntries() != 3 {
		t.Errorf("entries %d", f.TotalEntries())
	}
}

func TestLoadListsLeavesAFresherListAlone(t *testing.T) {
	dir := t.TempDir()
	writeList(filepath.Join(dir, "oisd.list"), []string{"old.example.com"})
	f := NewFilter(dir)
	f.LoadBase()
	f.setListSet(defaultLists[0], newHashSet([]string{"new.example.com"}), "e", "") // the updater got there first
	f.LoadLists()
	now := time.Now()
	if b, _ := f.Match("new.example.com", now); !b {
		t.Error("the updated list was overwritten by the older file")
	}
	if b, _ := f.Match("old.example.com", now); b {
		t.Error("the old copy came back")
	}
}

func TestSealHashSetIsExactAndSorted(t *testing.T) {
	h := make(hashSet, 0, 1000)
	for i := 0; i < 100; i++ {
		h = append(h, hashName(string(rune('a'+i%26))+"x.example"), uint64(i))
	}
	s := sealHashSet(h)
	for i := 1; i < len(s); i++ {
		if s[i] <= s[i-1] {
			t.Fatal("not sorted and unique")
		}
	}
	if cap(s) > len(s)+len(s)/16 {
		t.Errorf("kept %d slots for %d hashes", cap(s), len(s))
	}
}
