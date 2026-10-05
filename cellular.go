package main

// Read-only cellular page: the APN and data settings the stock firmware keeps (/usrdata/data/qcmap/mobileap_cfg.xml, /usrdata/data/usr/dial/dial_cfg.xml) and what the
// kernel shows of the uplink interface (addresses, carrier-grade NAT, counters). Uplink health, latency, usage and temperature are already in /status.json and the page
// joins them. Nothing here writes: an APN change goes through the carrier's data session and can cut the Orbic off, so it needs its own confirmed, rolled-back flow.
// What it cannot show: signal strength, band, serving cell and tower changes. The modem answers those only through its QMI/diag interfaces (the stock QCMAP_CLI
// returned error 0x2 when asked, 2026-10-02); the roadmap's own diag parser is the way to get them.

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type cellView struct {
	Iface     string   `json:"iface"`
	Up        bool     `json:"up"`
	MTU       int      `json:"mtu,omitempty"`
	IPv4      string   `json:"ipv4,omitempty"`
	CGNAT     bool     `json:"cgnat"` // the address is in 100.64.0.0/10: the carrier shares one public address among many customers
	IPv6      string   `json:"ipv6,omitempty"`
	DNS       []string `json:"carrier_dns,omitempty"`
	APN       string   `json:"apn,omitempty"`
	V4Profile int      `json:"v4_profile"`
	V6Profile int      `json:"v6_profile"`
	IPv4On    bool     `json:"ipv4_enabled"`
	IPv6On    bool     `json:"ipv6_enabled"`
	Roaming   bool     `json:"roaming_allowed"`
	AutoConn  bool     `json:"auto_connect"`
	DataOn    bool     `json:"data_switch"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxPackets uint64   `json:"rx_packets"`
	TxPackets uint64   `json:"tx_packets"`
	RxDrops   uint64   `json:"rx_drops"`
	TxDrops   uint64   `json:"tx_drops"`
	RxErrors  uint64   `json:"rx_errors"`
	TxErrors  uint64   `json:"tx_errors"`
	Missing   []string `json:"missing,omitempty"` // sources that could not be read
}

func xmlTag(raw, tag string) (string, bool) {
	m := regexp.MustCompile(`<` + tag + `>\s*([^<]*?)\s*</` + tag + `>`).FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func xmlInt(raw, tag string) int { s, _ := xmlTag(raw, tag); n, _ := strconv.Atoi(s); return n }

var cgnat = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

// parseNetDev picks one interface's counters out of /proc/net/dev.
func parseNetDev(text, iface string) (rxB, rxP, rxE, rxD, txB, txP, txE, txD uint64, ok bool) {
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		name, rest, found := strings.Cut(l, ":")
		if !found || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			return
		}
		n := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		return n(0), n(1), n(2), n(3), n(8), n(9), n(10), n(11), true
	}
	return
}

// buildCellView is pure apart from the interface it is handed: unit-tested.
func buildCellView(iface string, qcmap, dial, netdev string, addrs []net.Addr, up bool, mtu int, resolv string) cellView {
	v := cellView{Iface: iface, Up: up, MTU: mtu}
	if qcmap == "" {
		v.Missing = append(v.Missing, "the WWAN settings (mobileap_cfg.xml)")
	} else {
		v.APN, _ = xmlTag(qcmap, "APN")
		v.V4Profile, v.V6Profile = xmlInt(qcmap, "V4_UMTS_PROFILE_INDEX"), xmlInt(qcmap, "V6_UMTS_PROFILE_INDEX")
		v.IPv4On, v.IPv6On = xmlInt(qcmap, "EnableIPV4") == 1, xmlInt(qcmap, "EnableIPV6") == 1
		v.Roaming, v.AutoConn = xmlInt(qcmap, "Roaming") == 1, xmlInt(qcmap, "AutoConnect") == 1
	}
	if dial == "" {
		v.Missing = append(v.Missing, "the data switch (dial_cfg.xml)")
	} else {
		v.DataOn = xmlInt(dial, "dataswitch") == 1
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip4 := n.IP.To4(); ip4 != nil && v.IPv4 == "" {
				v.IPv4, v.CGNAT = n.IP.String(), cgnat.Contains(ip4)
			} else if ip4 == nil && n.IP.IsGlobalUnicast() && v.IPv6 == "" {
				v.IPv6 = n.IP.String()
			}
		}
	}
	if rb, rp, re, rd, tb, tp, te, td, ok := parseNetDev(netdev, iface); ok {
		v.RxBytes, v.RxPackets, v.RxErrors, v.RxDrops, v.TxBytes, v.TxPackets, v.TxErrors, v.TxDrops = rb, rp, re, rd, tb, tp, te, td
	} else {
		v.Missing = append(v.Missing, "the interface counters")
	}
	for _, l := range strings.Split(resolv, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "nameserver" {
			v.DNS = append(v.DNS, f[1])
		}
	}
	return v
}

func readCell() cellView {
	rd := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	up, mtu := false, 0
	var addrs []net.Addr
	if ifc, err := net.InterfaceByName("rmnet_data0"); err == nil {
		up, mtu = ifc.Flags&net.FlagUp != 0, ifc.MTU
		addrs, _ = ifc.Addrs()
	}
	return buildCellView("rmnet_data0", rd(*qcmapCfgFile), rd("/usrdata/data/usr/dial/dial_cfg.xml"), rd("/proc/net/dev"), addrs, up, mtu, rd(*dnsResolv))
}
