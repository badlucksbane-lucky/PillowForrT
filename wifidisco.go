package main

// Mass disconnect watch: the box cannot see 802.11 deauthentication frames themselves, but it can see their effect, because hostapd reports every station that
// leaves (`hostapd_cli all_sta`, the same command wifi.go already polls for the clients list). Five or more stations dropping within a few seconds, then usually
// rejoining once the attack stops, is the signature of a deauth flood or a jammer -- the usual first step before an evil twin, since a client that has been
// knocked off its real AP is the one that will join a look-alike. Honest limit, stated rather than hidden: a power blip on the hotspot's own radio empties the
// station list exactly the same way, so a drop that happens within moments of the box itself having just come up (low /proc/uptime) is not flagged -- it is
// filed as a boot, not an attack.
//
// This polls rather than hooks hostapd's control socket event stream (the way wifi.go already shells out to hostapd_cli for everything else): simpler, and the
// several-second polling period here is still well inside "a few seconds" for a flood that empties the station list and keeps it empty for the kick's duration.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	discoPollEvery  = 3 * time.Second
	discoWindow     = 10 * time.Second
	discoThreshold  = 5   // stations dropping inside the window to call it a mass disconnect
	discoMinUptimeS = 120 // below this, an empty station list is more likely the radio just coming up than an attack
)

func readUptimeS() int {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	u, _ := strconv.ParseFloat(f[0], 64)
	return int(u)
}

type discoFinding struct {
	T     int64    `json:"t"`
	Count int      `json:"count"`
	MACs  []string `json:"macs"`
}

type wifiDiscoWatch struct {
	mu       sync.Mutex
	stations func() string // both radios, hostapd_cli all_sta (wifi.go's env.stations)
	uptimeS  func() int
	now      func() time.Time
	emit     func(evt)
	prev     map[string]bool
	drops    []droppedMAC
	lastEv   time.Time
	finds    []discoFinding
	started  bool
}

type droppedMAC struct {
	mac string
	at  time.Time
}

func newWifiDiscoWatch(stations func() string) *wifiDiscoWatch {
	return &wifiDiscoWatch{stations: stations, uptimeS: readUptimeS, now: time.Now, prev: map[string]bool{},
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		}}
}

// poll reads the current station list and reports any newly-missing MACs as dropped. Pure enough to unit test by
// calling it directly with a fixed `now`.
func (w *wifiDiscoWatch) poll(now time.Time) {
	cur := map[string]bool{}
	for _, s := range parseStations(w.stations()) {
		cur[s.MAC] = true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.prev == nil {
		w.prev = map[string]bool{}
	}
	first := len(w.prev) == 0 && !w.started
	w.started = true
	for mac := range w.prev {
		if !cur[mac] {
			w.drops = append(w.drops, droppedMAC{mac: mac, at: now})
		}
	}
	w.prev = cur
	if first {
		w.drops = nil // nothing to compare the very first poll against
		return
	}
	cutoff := now.Add(-discoWindow)
	kept := w.drops[:0]
	seen := map[string]bool{}
	var macs []string
	for _, d := range w.drops {
		if d.at.After(cutoff) {
			kept = append(kept, d)
			if !seen[d.mac] {
				seen[d.mac] = true
				macs = append(macs, d.mac)
			}
		}
	}
	w.drops = kept
	if len(macs) < discoThreshold {
		return
	}
	if w.uptimeS() < discoMinUptimeS {
		return // the radio itself just came up: a power blip looks identical, so this is not flagged
	}
	if now.Sub(w.lastEv) < 5*time.Minute {
		return
	}
	w.lastEv = now
	f := discoFinding{T: now.Unix(), Count: len(macs), MACs: macs}
	w.finds = append(w.finds, f)
	if len(w.finds) > 50 {
		w.finds = w.finds[len(w.finds)-50:]
	}
	w.emit(evt{T: f.T, Kind: "wifi_mass_disconnect", Sev: sevAlert,
		Text:   fmt.Sprintf("%d Wi-Fi stations dropped off within a few seconds of each other: this is the usual effect of a deauthentication flood or a jammer, often the first step before an evil twin access point, though a power blip on the hotspot would look the same.", len(macs)),
		Public: "Several Wi-Fi devices dropped off the network at once"})
}

func (w *wifiDiscoWatch) Start() {
	go func() {
		for range time.Tick(discoPollEvery) {
			w.poll(w.now())
		}
	}()
}

type wifiDiscoView struct {
	Findings []discoFinding `json:"findings"`
}

func (w *wifiDiscoWatch) View() wifiDiscoView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := wifiDiscoView{Findings: []discoFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var wifiDiscoMgr *wifiDiscoWatch
