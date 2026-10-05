package main

// The system page: what the box is and how it is doing, read straight from /proc, /sys and the filesystem (no stock admin involved), plus a confirmed reboot.
// Deliberately absent: the IMEI, serial numbers and SIM identifiers (the page never needs them), and factory reset (not offered at all).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type sysDisk struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	TotalB uint64 `json:"total_b"`
	FreeB  uint64 `json:"free_b"`
	Note   string `json:"note,omitempty"`
}

type sysService struct {
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	State string `json:"state"` // running | not running | held (stopped on purpose)
	Note  string `json:"note,omitempty"`
}

type sysTemp struct {
	Name string  `json:"name"`
	C    float64 `json:"c"`
}

type sysBattery struct {
	Known bool `json:"known"`
	Level int  `json:"level"` // the firmware's own 0..n scale, as logged
	MV    int  `json:"mv"`
	TempC int  `json:"temp_c"`
}

type sysView struct {
	Product    string       `json:"product"`
	Firmware   string       `json:"firmware"`
	Kernel     string       `json:"kernel"`
	Tinyfwd    string       `json:"tinyfwd"`
	UptimeS    int          `json:"uptime_s"`
	Load       [3]float64   `json:"load"`
	MemTotalKB int          `json:"mem_total_kb"`
	MemAvailKB int          `json:"mem_avail_kb"`
	Disks      []sysDisk    `json:"disks"`
	Temps      []sysTemp    `json:"temps"`
	Battery    sysBattery   `json:"battery"`
	Services   []sysService `json:"services"`
	Now        string       `json:"now"`
}

func propVal(text, key string) string {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return v
		}
	}
	return ""
}

func parseMeminfo(text string) (total, avail int) {
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			n, _ := strconv.Atoi(f[1])
			switch f[0] {
			case "MemTotal:":
				total = n
			case "MemAvailable:":
				avail = n
			}
		}
	}
	return
}

var odmRe = regexp.MustCompile(`odm_notify: volt_avg=(\d+) bat_level=(\d+) bat_temperature=(-?\d+)`)

// parseBattery reads the newest battery line the firmware logs to the kernel ring.
func parseBattery(dmesg string) sysBattery {
	m := odmRe.FindAllStringSubmatch(dmesg, -1)
	if len(m) == 0 {
		return sysBattery{}
	}
	l := m[len(m)-1]
	mv, _ := strconv.Atoi(l[1])
	lv, _ := strconv.Atoi(l[2])
	t, _ := strconv.Atoi(l[3])
	return sysBattery{Known: true, Level: lv, MV: mv, TempC: t}
}

// serviceTable says which of the processes that make the Orbic work are alive. `procs` is comm names plus full command lines.
func serviceTable(comms, stopped map[string]bool, cmdlines []string) []sysService {
	has := func(sub string) bool {
		for _, c := range cmdlines {
			if strings.Contains(c, sub) {
				return true
			}
		}
		return false
	}
	svc := func(name string, up bool, note string) sysService {
		st := "not running"
		if up {
			st = "running"
		}
		return sysService{name, up, st, note}
	}
	upgrade := sysService{"carrier updates (upgrade)", comms["upgrade"] && stopped["upgrade"], "not running", "the guard keeps it stopped on purpose, so no carrier firmware update can start"}
	if comms["upgrade"] && stopped["upgrade"] {
		upgrade.State = "held"
	} else if comms["upgrade"] {
		upgrade.State, upgrade.Note = "running", "it should be held stopped: the guard will stop it within a minute"
	}
	return []sysService{
		svc("tinyfwd (proxy, DNS filter, this page)", comms["tinyfwd"], ""),
		svc("dnsmasq (DHCP and DNS)", comms["dnsmasq"], ""),
		svc("hostapd, 2.4 GHz", has("hostapd_wlan0.conf"), ""),
		svc("hostapd, 5 GHz", has("hostapd_wlan1.conf"), "only runs while the 5 GHz network is on"),
		svc("wland (Wi-Fi manager)", comms["wland"], ""),
		svc("QCMAP (the cellular data connection)", has("QCMAP_ConnectionManager"), ""),
		svc("dropbear (ssh)", comms["dropbear"], ""),
		svc("guard (firewall, reservations, FOTA hold)", has("wpad-guard.sh"), ""),
		svc("stock admin (goahead, port 81/444)", comms["goahead"], ""),
		upgrade,
	}
}
func scanProcs(root string) (comms, stopped map[string]bool, lines []string) {
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

func readDisk(name, path, note string) (sysDisk, bool) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return sysDisk{}, false
	}
	return sysDisk{Name: name, Path: path, TotalB: uint64(s.Blocks) * uint64(s.Bsize), FreeB: uint64(s.Bavail) * uint64(s.Bsize), Note: note}, true
}

func readSystem() sysView {
	rd := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	v := sysView{Tinyfwd: version, Now: time.Now().In(schedLoc()).Format("Mon 2006-01-02 15:04 MST")}
	bp := rd("/build.prop")
	v.Product, v.Firmware = propVal(bp, "ro.product.name"), propVal(bp, "ro.build.version.release")
	if f := strings.Fields(rd("/proc/version")); len(f) >= 3 {
		v.Kernel = f[2]
	}
	if f := strings.Fields(rd("/proc/uptime")); len(f) > 0 {
		u, _ := strconv.ParseFloat(f[0], 64)
		v.UptimeS = int(u)
	}
	if f := strings.Fields(rd("/proc/loadavg")); len(f) >= 3 {
		for i := 0; i < 3; i++ {
			v.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	v.MemTotalKB, v.MemAvailKB = parseMeminfo(rd("/proc/meminfo"))
	for _, d := range [][3]string{{"System (read-only flash)", "/", "almost full: nothing should be added here"}, {"Data (flash, wears)", "/data", ""}, {"Settings", "/usrdata", ""}, {"RAM disk (logs, gone at reboot)", "/var/volatile", ""}} {
		if x, ok := readDisk(d[0], d[1], d[2]); ok {
			v.Disks = append(v.Disks, x)
		}
	}
	zs, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	sort.Strings(zs)
	for _, z := range zs {
		if t, err := strconv.ParseFloat(strings.TrimSpace(rd(z+"/temp")), 64); err == nil {
			if t > 1000 { // some kernels report millidegrees
				t /= 1000
			}
			v.Temps = append(v.Temps, sysTemp{strings.TrimSpace(rd(z + "/type")), t})
		}
	}
	out, _ := run("dmesg")
	v.Battery = parseBattery(out)
	comms, stopped, lines := scanProcs("/proc")
	v.Services = serviceTable(comms, stopped, lines)
	return v
}

// reboot is confirmed twice (the page and the typed word) and runs detached after a short delay so the reply gets out first.
var rebootNow = func() error {
	_, err := run("sh", "-c", "(sleep 3; reboot) >/dev/null 2>&1 &")
	return err
}

func doReboot(confirm string) error {
	if confirm != "reboot" {
		return errors.New(`send {"confirm":"reboot"} to reboot`)
	}
	if err := rebootNow(); err != nil {
		return fmt.Errorf("could not start the reboot: %v", err)
	}
	return nil
}
