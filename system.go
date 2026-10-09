package main

// The system page: what the box is and how it is doing, read straight from /proc, /sys and the filesystem (no stock admin involved), plus a confirmed reboot.
// Deliberately absent: the IMEI, serial numbers and SIM identifiers (the page never needs them), and factory reset (not offered at all).

import (
	"bytes"
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

// serviceTable says which of the processes that make the box work are alive. `procs` is comm names plus full command lines.
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

// scanProcs lists the running processes under root (/proc): every command name, the names of those that are stopped, and the command lines of the user-space ones. Two small reads
// a process (one for a kernel thread), through bare system calls and one reused buffer: it runs every 20 s on a core that is busy enough.
func scanProcs(root string) (comms, stopped map[string]bool, lines []string) {
	comms, stopped = map[string]bool{}, map[string]bool{}
	d, err := os.Open(root)
	if err != nil {
		return comms, stopped, nil
	}
	names, _ := d.Readdirnames(-1) // not os.ReadDir: that sorts and allocates an entry for each of the 60-odd non-process names too
	d.Close()
	buf := make([]byte, 4096)
	for _, name := range names {
		if !allDigits(name) {
			continue
		}
		n := readProcFile(root+"/"+name+"/stat", buf)
		comm, state, kthread, ok := parseProcStat(buf[:n])
		if !ok {
			continue
		}
		if !comms[string(comm)] { // the lookup does not allocate; only a name seen for the first time does
			comms[string(comm)] = true
		}
		if state == 'T' {
			stopped[string(comm)] = true
		}
		if kthread { // a kernel thread has no command line: half the entries on the box
			continue
		}
		if n = readProcFile(root+"/"+name+"/cmdline", buf); n > 0 {
			for i := 0; i < n; i++ {
				if buf[i] == 0 {
					buf[i] = ' '
				}
			}
			lines = append(lines, string(buf[:n]))
		}
	}
	return comms, stopped, lines
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// readProcFile reads up to len(buf) bytes of a small /proc file in three system calls (open, read, close; os.ReadFile makes five and allocates a File and a buffer each time). It returns 0 for a file that is gone.
func readProcFile(path string, buf []byte) int {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	n, err := syscall.Read(fd, buf)
	syscall.Close(fd)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

const pfKthread = 0x00200000

// parseProcStat reads what scanProcs needs from /proc/PID/stat: "pid (comm) S ppid pgrp session tty tpgid flags ...". The command name is whatever sits between the first "(" and the LAST ")" (it may contain either).
func parseProcStat(b []byte) (comm []byte, state byte, kthread, ok bool) {
	open, end := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if open < 0 || end < open || end+2 >= len(b) {
		return nil, 0, false, false
	}
	comm, state = b[open+1:end], b[end+2]
	// after the state and the space that follows it: ppid pgrp session tty tpgid flags
	if end+4 > len(b) {
		return comm, state, false, true
	}
	rest, skip := b[end+4:], 5
	for skip > 0 {
		i := bytes.IndexByte(rest, ' ')
		if i < 0 {
			return comm, state, false, true
		}
		rest, skip = rest[i+1:], skip-1
	}
	var flags uint64
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		flags = flags*10 + uint64(c-'0')
	}
	return comm, state, flags&pfKthread != 0, true
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
