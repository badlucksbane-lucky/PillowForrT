package main

// Vitals: a log line every 15 s with the daemon's load, memory and CPU, and a heap profile on the API. The box has frozen under load with nothing in the log to say why;
// the last vitals line before a gap shows what it was doing, and the profile shows what holds the heap.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"
)

const vitalsEvery = 15 * time.Second

// selfCPUTicks is this process's user+system CPU time in clock ticks (the 14th and 15th fields of /proc/self/stat, counted after the closing bracket of the command name).
func selfCPUTicks() uint64 {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 13 {
		return 0
	}
	u, _ := strconv.ParseUint(f[11], 10, 64)
	k, _ := strconv.ParseUint(f[12], 10, 64)
	return u + k
}

// vitalsLine formats one sample. cpuPct is this process's share of one core over the interval; gcs and gcPause are the garbage collections and total pause in the same interval;
// busy (0 to 1) is the whole box's CPU share over the last ten seconds, the number the torrent bridge sheds load on (btload.go).
func vitalsLine(load, cpuPct float64, m *runtime.MemStats, goroutines int, availKB uint64, gcs uint32, gcPause time.Duration, busy float64) string {
	return fmt.Sprintf("vitals load=%.2f cpu=%.0f%% heap=%dKB inuse=%dKB sys=%dKB gcs=%d gcpause=%dms goroutines=%d avail=%dKB busy=%.0f%%",
		load, cpuPct, m.HeapAlloc>>10, m.HeapInuse>>10, m.Sys>>10, gcs, gcPause.Milliseconds(), goroutines, availKB, busy*100)
}

func startVitals() {
	go func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		lastTicks, lastGC, lastPause, last := selfCPUTicks(), m.NumGC, m.PauseTotalNs, time.Now()
		for range time.Tick(vitalsEvery) {
			runtime.ReadMemStats(&m)
			now, ticks := time.Now(), selfCPUTicks()
			secs := now.Sub(last).Seconds()
			cpu := 0.0
			if secs > 0 { // clock ticks are 100 per second on Linux
				cpu = float64(ticks-lastTicks) / 100 / secs * 100
			}
			log.Print(vitalsLine(loadAvg1(), cpu, &m, runtime.NumGoroutine(), memAvailKB(), m.NumGC-lastGC, time.Duration(m.PauseTotalNs-lastPause), btBusyNow()))
			lastTicks, lastGC, lastPause, last = ticks, m.NumGC, m.PauseTotalNs, now
		}
	}()
}

// handleDebug serves /api/debug/heap (a pprof heap profile: `go tool pprof -sample_index=inuse_space ./tinyfwd heap.pb.gz`) and /api/debug/goroutines (every stack, as text).
// It sits behind the same sign-in or X-UI-Token as the rest of the API.
func handleDebug(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	secureHeaders(w)
	switch path {
	case "debug/heap":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="heap.pb.gz"`)
		pprof.Lookup("heap").WriteTo(w, 0)
	case "debug/goroutines":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		pprof.Lookup("goroutine").WriteTo(w, 1)
	default:
		http.NotFound(w, r)
	}
}
