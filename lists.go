package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

// listUpdater downloads the block lists itself (from the Orbic, over its own uplink), validates them, writes the compiled copy to flash and swaps it in.
type listUpdater struct {
	f      *Filter
	client *http.Client
	mu     sync.Mutex
	busy   map[string]bool
}

func newListUpdater(f *Filter) *listUpdater {
	return &listUpdater{f: f, busy: map[string]bool{}, client: &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12},
			DialContext:         ownDial, // follows the state: tunnel, Tor or (with a warning) the cellular link; blocked when the kill switch says so (owndial.go)
			TLSHandshakeTimeout: 20 * time.Second,
			DisableKeepAlives:   true, // a download a day: nothing worth pooling, and a pooled connection would outlive a change of route
		},
	}}
}

const minListEntries = 10000 // a list far smaller than this is a broken download: keep the old one

func (u *listUpdater) UpdateOne(sp listSpec, force bool) error {
	u.mu.Lock()
	if u.busy[sp.Name] {
		u.mu.Unlock()
		return fmt.Errorf("%s is already updating", sp.Name)
	}
	u.busy[sp.Name] = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); delete(u.busy, sp.Name); u.mu.Unlock(); debug.FreeOSMemory() }()

	req, _ := http.NewRequest("GET", sp.URL, nil)
	req.Header.Set("User-Agent", "heimdallstone/0.3")
	u.f.mu.RLock()
	if l := u.f.lists[sp.Name]; l != nil && !force {
		if l.ETag != "" {
			req.Header.Set("If-None-Match", l.ETag)
		}
		if l.LastMod != "" {
			req.Header.Set("If-Modified-Since", l.LastMod)
		}
	}
	u.f.mu.RUnlock()
	resp, err := u.client.Do(req)
	if err != nil {
		u.f.setListErr(sp.Name, err.Error())
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		u.f.touchList(sp.Name)
		return nil
	}
	if resp.StatusCode != 200 {
		err := fmt.Errorf("%s answered HTTP %d", sp.URL, resp.StatusCode)
		u.f.setListErr(sp.Name, err.Error())
		return err
	}
	path := filepath.Join(u.f.dir, sp.Name+".list")
	set, err := compileStream(io.LimitReader(resp.Body, 64<<20), sp.Format, path+".tmp", maxListEntries)
	min := sp.Min
	if min == 0 {
		min = minListEntries
	}
	if err == nil && len(set) < min {
		os.Remove(path + ".tmp")
		err = fmt.Errorf("only %d entries parsed (expected at least %d): keeping the old list", len(set), min)
	}
	if err != nil {
		u.f.setListErr(sp.Name, err.Error())
		return err
	}
	if err := u.f.setListSet(sp, set, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")); err != nil {
		os.Remove(path + ".tmp")
		u.f.setListErr(sp.Name, err.Error())
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		u.f.setListErr(sp.Name, "could not save: "+err.Error())
		return err
	}
	log.Printf("list %s updated: %d entries", sp.Name, len(set))
	return nil
}

// UpdateAll updates every list; failures are returned per list and recorded on the list (shown on the web page).
func (u *listUpdater) UpdateAll(force bool) map[string]error {
	out := map[string]error{}
	for _, sp := range defaultLists {
		if !u.f.wanted(sp.Name) {
			continue
		}
		if err := u.UpdateOne(sp, force); err != nil {
			out[sp.Name] = err
			log.Printf("list %s: %v", sp.Name, err)
		}
	}
	return out
}

// Schedule fetches any missing list shortly after start (retrying every 10 minutes while the uplink is not ready), then re-checks every 24 h.
func (u *listUpdater) Schedule() {
	go func() {
		time.Sleep(45 * time.Second)
		for {
			missing := false
			for _, l := range u.f.Lists() {
				if l.Entries == 0 && l.On {
					missing = true
				}
			}
			if !missing {
				break
			}
			u.UpdateAll(false)
			time.Sleep(10 * time.Minute)
		}
		for {
			time.Sleep(24 * time.Hour)
			u.UpdateAll(false)
		}
	}()
}
