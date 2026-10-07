package main

// The stock admin as a tripwire. Once the stock admin is switched off for the network (stockadmin.go), its ports 81 and 444 are rejected in the firewall and no honest
// device has any reason to open them: the page it served is gone from the LAN, nothing links to it, and a browser never wanders there by itself. Anything that still knocks
// is looking for the factory login page: a scanner that knows the model, a worm with a list of router default credentials, or a person on the Wi-Fi being curious. The knock
// is read passively through an AF_PACKET socket filtered in-kernel to a TCP SYN for either port, before the firewall's reject fires, so this adds no listener and sends
// nothing. The first touch from a source raises an event "to look at", at most once per source per 10 minutes, with the port it tried. While the stock admin is switched
// on, those ports carry the relayed admin page and a knock means nothing, so the watch stays quiet. Honest limit: a source that only probes 192.168.1.1 on 80 or 443 lands on
// this page, which is ordinary, and is not counted here.

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var stockAdminPorts = []int{81, 444}

// bpfAdminKnock accepts an IPv4 TCP SYN (without ACK) to port 81 or 444 and nothing else.
func bpfAdminKnock() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                    // 0  ldh [12]           ethertype
		{Code: 0x15, Jt: 0, Jf: 10, K: 0x0800}, // 1  jeq IPv4 -> 2, else drop (12)
		{Code: 0x30, K: 23},                    // 2  ldb [23]           IP protocol
		{Code: 0x15, Jt: 0, Jf: 8, K: 6},       // 3  jeq TCP -> 4, else drop (12)
		{Code: 0xb1, K: 14},                    // 4  ldx 4*([14]&0xf)   IP header length
		{Code: 0x50, K: 27},                    // 5  ldb [x+27]         TCP flags
		{Code: 0x54, K: 0x12},                  // 6  and SYN|ACK
		{Code: 0x15, Jt: 0, Jf: 4, K: 0x02},    // 7  jeq SYN only -> 8, else drop (12)
		{Code: 0x48, K: 16},                    // 8  ldh [x+16]         TCP destination port
		{Code: 0x15, Jt: 1, Jf: 0, K: 81},      // 9  jeq 81 -> accept (11), else -> 10
		{Code: 0x15, Jt: 0, Jf: 1, K: 444},     // 10 jeq 444 -> accept (11), else drop (12)
		{Code: 0x06, K: 65535},                 // 11 accept
		{Code: 0x06, K: 0},                     // 12 drop
	}
}

// parseAdminKnock reads the source of one frame that passed the filter and the port it aimed at.
func parseAdminKnock(b []byte) (mac, ip string, port int, ok bool) {
	if len(b) < 34 {
		return "", "", 0, false
	}
	ihl := int(b[14]&0x0f) * 4
	if ihl < 20 || len(b) < 14+ihl+4 {
		return "", "", 0, false
	}
	return macStr(b[6:12]), net.IP(b[26:30]).String(), int(binary.BigEndian.Uint16(b[14+ihl+2 : 14+ihl+4])), true
}

type adminKnock struct {
	T    int64  `json:"t"`
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
	Port int    `json:"port"`
}

type adminTrip struct {
	mu      sync.Mutex
	knocks  []adminKnock
	lastEv  map[string]time.Time
	own     map[string]bool
	now     func() time.Time
	emit    func(evt)
	nameOf  func(mac string) string
	armed   func() bool // the stock admin is switched off, so a knock means something
	capOK   bool
	capOnce bool
}

func newAdminTrip() *adminTrip {
	return &adminTrip{lastEv: map[string]time.Time{}, own: map[string]bool{"192.168.1.1": true, "192.168.1.254": true, "192.168.1.253": true, "127.0.0.1": true}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		nameOf: func(mac string) string {
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					if r.MAC == mac {
						return r.Name
					}
				}
			}
			return ""
		},
		armed: func() bool { return stockAdminOff != nil && stockAdminOff() }}
}

// Observe records one knock and raises the event, once per source per 10 minutes.
func (a *adminTrip) Observe(mac, ip string, port int, now time.Time) {
	if a.own[ip] || !a.armed() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.knocks = append(a.knocks, adminKnock{T: now.Unix(), IP: ip, MAC: mac, Port: port})
	if len(a.knocks) > 100 {
		a.knocks = a.knocks[len(a.knocks)-100:]
	}
	for k, t := range a.lastEv {
		if now.Sub(t) > time.Hour {
			delete(a.lastEv, k)
		}
	}
	if t, ok := a.lastEv[ip]; ok && now.Sub(t) < 10*time.Minute {
		return
	}
	a.lastEv[ip] = now
	who := ip
	if n := a.nameOf(mac); n != "" {
		who += " (" + n + ")"
	} else if mac != "" {
		who += " (" + mac + ")"
	}
	a.emit(evt{T: now.Unix(), Kind: "stock_admin_probe", Sev: sevAttention, Text: fmt.Sprintf("%s knocked on the stock admin's port %d, which is switched off: nothing on the network has a reason to, so something is looking for the factory login page.", who, port), Public: "Something on the network probed the router's switched-off factory admin port"})
}

func (a *adminTrip) Start() {
	a.mu.Lock()
	if a.capOnce {
		a.mu.Unlock()
		return
	}
	a.capOnce = true
	a.mu.Unlock()
	go func() {
		for {
			if err := a.capture(); err != nil {
				log.Printf("stock admin tripwire: %v (retrying in a minute)", err)
			}
			a.mu.Lock()
			a.capOK = false
			a.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (a *adminTrip) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfAdminKnock()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	a.mu.Lock()
	a.capOK = true
	a.mu.Unlock()
	buf := make([]byte, 128)
	for {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n > len(buf) {
			n = len(buf)
		}
		if mac, ip, port, ok := parseAdminKnock(buf[:n]); ok {
			a.Observe(mac, ip, port, a.now())
		}
	}
}

type adminTripView struct {
	Armed     bool         `json:"armed"` // the stock admin is switched off
	CaptureOK bool         `json:"capture_ok"`
	Knocks    []adminKnock `json:"knocks"`
	Sources   int          `json:"sources"` // distinct sources in the last hour
	Ports     string       `json:"ports"`
}

func (a *adminTrip) View() adminTripView {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := adminTripView{Armed: a.armed(), CaptureOK: a.capOK, Knocks: []adminKnock{}, Ports: strconv.Itoa(stockAdminPorts[0]) + " and " + strconv.Itoa(stockAdminPorts[1])}
	seen := map[string]bool{}
	cut := a.now().Add(-time.Hour).Unix()
	for i := len(a.knocks) - 1; i >= 0; i-- {
		k := a.knocks[i]
		v.Knocks = append(v.Knocks, k)
		if k.T >= cut && !seen[k.IP] {
			seen[k.IP] = true
			v.Sources++
		}
	}
	return v
}

var adminTripMgr *adminTrip
