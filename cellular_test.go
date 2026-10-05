package main

import (
	"net"
	"strings"
	"testing"
)

const cellQ = `<c><EnableIPV4>1</EnableIPV4><EnableIPV6>1</EnableIPV6><AutoConnect>0</AutoConnect><Roaming>1</Roaming><V4_UMTS_PROFILE_INDEX>3</V4_UMTS_PROFILE_INDEX><V6_UMTS_PROFILE_INDEX>3</V6_UMTS_PROFILE_INDEX><APN>VZWINTERNET</APN><DDNSPassword>secret</DDNSPassword></c>`
const cellND = "Inter-|   Receive\n face |bytes\n rmnet_data0: 2726173391 1940092 3 4 0 0 0 0 469325442 606588 5 6 0 0 0 0\n   wlan0: 1 2 0 0 0 0 0 0 3 4 0 0 0 0 0 0\n"

func TestCellView(t *testing.T) {
	_, a4, _ := net.ParseCIDR("100.110.98.3/29")
	a4.IP = net.ParseIP("100.110.98.3")
	_, a6, _ := net.ParseCIDR("2600:100a:b03e:ff2::/64")
	a6.IP = net.ParseIP("2600:100a:b03e:ff2:5551:9cb6:fe78:7b98")
	v := buildCellView("rmnet_data0", cellQ, "<d><dataswitch>1</dataswitch></d>", cellND, []net.Addr{a6, a4}, true, 1428, "nameserver 198.224.1.1\nnameserver 198.224.1.2\n")
	if v.APN != "VZWINTERNET" || v.V4Profile != 3 || !v.Roaming || v.AutoConn || !v.DataOn || !v.IPv4On || !v.IPv6On {
		t.Errorf("settings %+v", v)
	}
	if v.IPv4 != "100.110.98.3" || !v.CGNAT || !strings.HasPrefix(v.IPv6, "2600:100a:") || len(v.DNS) != 2 {
		t.Errorf("link %+v", v)
	}
	if v.RxBytes != 2726173391 || v.RxErrors != 3 || v.RxDrops != 4 || v.TxBytes != 469325442 || v.TxErrors != 5 || v.TxDrops != 6 || len(v.Missing) != 0 {
		t.Errorf("counters %+v", v)
	}
	if strings.Contains(strings.ToLower(strings.Join(v.DNS, "")), "secret") {
		t.Error("leak")
	}
	e := buildCellView("rmnet_data0", "", "", "", nil, false, 0, "")
	if len(e.Missing) != 3 || e.Up {
		t.Errorf("missing sources not reported: %+v", e)
	}
	pub := buildCellView("x", cellQ, "", cellND, []net.Addr{&net.IPNet{IP: net.ParseIP("8.8.8.8"), Mask: net.CIDRMask(24, 32)}}, true, 0, "")
	if pub.CGNAT {
		t.Error("a public address flagged as carrier-grade NAT")
	}
}
