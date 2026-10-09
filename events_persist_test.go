package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// persistStore is an event store whose file writes go through hook, and a handle on what was written.
func waitFor(t *testing.T, c chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for " + what)
	}
}

// persistStore is an event store whose file writes go through hook, and a handle on what was written.
func persistStore(t *testing.T, hook func(b []byte) error) (*eventStore, *atomic.Int64) {
	var writes atomic.Int64
	dir := t.TempDir()
	s := &eventStore{path: filepath.Join(dir, "e.json"), cfgPath: filepath.Join(dir, "n.json"), lastOf: map[string]time.Time{}, now: time.Now,
		writeFile: func(path string, b []byte, mode os.FileMode) error {
			writes.Add(1)
			if hook != nil {
				if err := hook(b); err != nil {
					return err
				}
			}
			return writeFileAtomic(path, b, mode)
		}}
	t.Cleanup(s.Flush) // runs before the temporary directory is removed: nothing may still be writing into it
	return s, &writes
}

func fileEvents(t *testing.T, s *eventStore) []evt {
	b, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	var f eventsFileV2
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Events
}

func TestAddDoesNotWaitForTheDisk(t *testing.T) {
	inWrite, release := make(chan struct{}, 1), make(chan struct{})
	s, _ := persistStore(t, func([]byte) error {
		select {
		case inWrite <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	defer func() { close(release); s.Flush() }() // let the stuck write finish, and the queued ones after it, before the test ends
	done := make(chan struct{})
	go func() { // everything runs in a goroutine, so that a store that does wait for the disk fails this test instead of hanging it
		s.Add([]evt{{Kind: "first", Sev: sevInfo}})
		<-inWrite // the writer is now stuck inside the first write
		for i := 0; i < 50; i++ {
			s.Add([]evt{{Kind: "burst", Sev: sevInfo}}) // none of these may wait for the stuck write
		}
		s.View() // nor may a page view
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Add waited for the file write")
	}
}

func TestABurstIsWrittenInFewWritesAndNothingIsLost(t *testing.T) {
	inWrite, release := make(chan struct{}, 1), make(chan struct{})
	first := true
	var mu sync.Mutex
	s, writes := persistStore(t, func([]byte) error {
		mu.Lock()
		stall := first
		first = false
		mu.Unlock()
		if stall {
			inWrite <- struct{}{}
			<-release
		}
		return nil
	})
	s.Add([]evt{{Kind: "first", Sev: sevInfo}})
	waitFor(t, inWrite, "the writer to start its first write")
	for i := 0; i < 50; i++ {
		s.Add([]evt{{Kind: "burst", Sev: sevInfo}})
	}
	close(release)
	s.Flush()
	if got := fileEvents(t, s); len(got) != 51 {
		t.Fatalf("the file holds %d events, want 51", len(got))
	}
	if n := writes.Load(); n > 4 {
		t.Errorf("51 events cost %d file writes: bursts must coalesce", n)
	}
	if c := s.Chain(); !c.OK {
		t.Errorf("chain: %+v", c)
	}
}

func TestMarkingSeenWritesOnlyWhenSomethingChanged(t *testing.T) {
	s, writes := persistStore(t, nil)
	s.Add([]evt{{Kind: "a", Sev: sevInfo}, {Kind: "b", Sev: sevInfo}})
	s.Flush()
	n0 := writes.Load()
	if s.MarkSeenKinds([]string{"nothing-like-this"}) != 0 {
		t.Fatal("matched something")
	}
	s.Flush()
	if writes.Load() != n0 {
		t.Error("marking nothing must not write the file")
	}
	s.MarkSeen()
	s.Flush()
	n1 := writes.Load()
	if n1 != n0+1 {
		t.Errorf("marking two events seen: %d writes", n1-n0)
	}
	s.MarkSeen() // all already seen
	s.MarkSeenKinds([]string{"a"})
	s.Flush()
	if writes.Load() != n1 {
		t.Error("marking what is already seen must not write the file")
	}
	for _, e := range fileEvents(t, s) {
		if !e.Seen {
			t.Error("the file lacks a seen flag")
		}
	}
}

func TestAFailedWriteIsTriedAgain(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	s, writes := persistStore(t, func([]byte) error {
		if fail.Load() {
			return errors.New("disk full")
		}
		return nil
	})
	s.Add([]evt{{Kind: "a", Sev: sevInfo}})
	s.Flush()
	if _, err := os.Stat(s.path); err == nil {
		t.Fatal("a failed write left a file")
	}
	fail.Store(false)
	s.Flush() // nothing new has been added, but the file is still behind
	if got := fileEvents(t, s); len(got) != 1 {
		t.Fatalf("after the retry the file holds %d events", len(got))
	}
	n := writes.Load()
	s.Flush()
	if writes.Load() != n {
		t.Error("an up-to-date file must not be written again")
	}
}

// The file must never go backwards: writers and Flush run together, each write takes its snapshot only after it holds the file lock.
func TestTheFileNeverGoesBackwards(t *testing.T) {
	var lastID atomic.Int64
	lastID.Store(-1)
	var bad atomic.Bool
	s, _ := persistStore(t, func(b []byte) error {
		var f eventsFileV2
		json.Unmarshal(b, &f)
		id := int64(f.Events[len(f.Events)-1].ID)
		if id < lastID.Load() {
			bad.Store(true)
		}
		lastID.Store(id)
		time.Sleep(time.Duration(id%3) * time.Millisecond) // slow, unevenly
		return nil
	})
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				s.Add([]evt{{Kind: "x", Sev: sevInfo}})
				if i%7 == 0 {
					s.Flush()
				}
			}
		}()
	}
	wg.Wait()
	s.Flush()
	if bad.Load() {
		t.Error("an older snapshot was written after a newer one")
	}
	got := fileEvents(t, s)
	if len(got) != 100 || got[len(got)-1].ID != 239 {
		t.Errorf("file: %d events, last id %d (want the newest 100 of 240)", len(got), got[len(got)-1].ID)
	}
	if c := s.Chain(); !c.OK {
		t.Errorf("chain: %+v", c)
	}
}
