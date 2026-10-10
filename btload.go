package main

// How busy the box is, for the torrent bridge's load shedding (no new peer and no new lookup while it is too busy).
//
// The one-minute load average is the wrong measure on this box: kernel threads (kworker, the Wi-Fi driver, spi) sit in uninterruptible I/O wait and count as load while the CPU is
// idle, so it read 5 to 6 with the core 70 % idle and the bridge refused every peer. This is the share of CPU time spent working (user, nice, system, interrupts) over the last ten
// seconds, from /proc/stat; time waiting for I/O counts as idle. It is a fraction of the one core, 0 to 1.

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	btBusyEvery  = 2 * time.Second
	btBusyWindow = 5 // samples, so the last ten seconds
)

type cpuTimes struct{ busy, total uint64 }

// parseCPULine reads the first line of /proc/stat: "cpu user nice system idle iowait irq softirq steal ...".
func parseCPULine(s string) (cpuTimes, bool) {
	f := strings.Fields(s)
	if len(f) < 5 || f[0] != "cpu" {
		return cpuTimes{}, false
	}
	var v [8]uint64 // user nice system idle iowait irq softirq steal; older kernels give fewer
	for i := 0; i < len(v) && i+1 < len(f); i++ {
		n, err := strconv.ParseUint(f[i+1], 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		v[i] = n
	}
	busy := v[0] + v[1] + v[2] + v[5] + v[6] + v[7]
	return cpuTimes{busy: busy, total: busy + v[3] + v[4]}, true
}

func readCPUTimes() (cpuTimes, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return parseCPULine(line)
}

// busyShare is the fraction of the time between two readings that the CPU spent working.
func busyShare(prev, cur cpuTimes) (float64, bool) {
	if cur.total <= prev.total || cur.busy < prev.busy {
		return 0, false
	}
	return float64(cur.busy-prev.busy) / float64(cur.total-prev.total), true
}

var btBusy struct {
	once sync.Once
	mu   sync.Mutex
	ring [btBusyWindow]float64
	n, i int
}

func btBusyAdd(f float64) {
	btBusy.mu.Lock()
	btBusy.ring[btBusy.i] = f
	btBusy.i = (btBusy.i + 1) % btBusyWindow
	if btBusy.n < btBusyWindow {
		btBusy.n++
	}
	btBusy.mu.Unlock()
}

// btBusyNow is the average busy share over the last ten seconds (0 until the first sample, or if /proc/stat cannot be read: it then sheds nothing). The sampler starts on first use.
func btBusyNow() float64 {
	btBusy.once.Do(func() {
		go func() {
			prev, ok := readCPUTimes()
			for range time.Tick(btBusyEvery) {
				cur, ok2 := readCPUTimes()
				if ok && ok2 {
					if f, good := busyShare(prev, cur); good {
						btBusyAdd(f)
					}
				}
				prev, ok = cur, ok2
			}
		}()
	})
	btBusy.mu.Lock()
	defer btBusy.mu.Unlock()
	if btBusy.n == 0 {
		return 0
	}
	var sum float64
	for _, f := range btBusy.ring[:btBusy.n] {
		sum += f
	}
	return sum / float64(btBusy.n)
}
