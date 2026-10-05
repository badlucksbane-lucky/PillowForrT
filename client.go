package main

// Who asked. dnsmasq (add-subnet=32,128 in dnsmasq.conf) tags each query it forwards to the stub with an EDNS Client Subnet option that holds the asking
// device's address. The stub reads it for the per-device counters, and strips it before the query goes upstream, so Quad9 never sees a device address.

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const ecsOption = 8

// splitClient returns the device address carried in the query's ECS option ("" when there is none) and the query without that option.
func splitClient(q []byte, qend int) (string, []byte) {
	if len(q) < 12 || qend < 12 || qend > len(q) {
		return "", q
	}
	ar := int(binary.BigEndian.Uint16(q[10:12]))
	off := qend
	for i := 0; i < ar; i++ {
		n, err := skipName(q, off)
		if err != nil || n+10 > len(q) {
			return "", q
		}
		typ := binary.BigEndian.Uint16(q[n : n+2])
		rdlen := int(binary.BigEndian.Uint16(q[n+8 : n+10]))
		rdStart, rdEnd := n+10, n+10+rdlen
		if rdEnd > len(q) {
			return "", q
		}
		if typ == qtOPT {
			var client string
			var kept []byte
			found := false
			for p := rdStart; p+4 <= rdEnd; {
				code := int(binary.BigEndian.Uint16(q[p : p+2]))
				l := int(binary.BigEndian.Uint16(q[p+2 : p+4]))
				if p+4+l > rdEnd {
					return "", q
				}
				if code == ecsOption && l >= 4 {
					found = true
					fam := binary.BigEndian.Uint16(q[p+4 : p+6])
					addr := q[p+8 : p+4+l]
					var ip net.IP
					if fam == 1 && len(addr) <= 4 {
						ip = append(append(net.IP{}, addr...), make([]byte, 4-len(addr))...)
					} else if fam == 2 && len(addr) <= 16 {
						ip = append(append(net.IP{}, addr...), make([]byte, 16-len(addr))...)
					}
					if ip != nil {
						client = ip.String()
					}
				} else {
					kept = append(kept, q[p:p+4+l]...)
				}
				p += 4 + l
			}
			if !found {
				return "", q
			}
			out := append([]byte(nil), q[:n+8]...)
			out = append(out, byte(len(kept)>>8), byte(len(kept)))
			out = append(out, kept...)
			out = append(out, q[rdEnd:]...)
			return client, out
		}
		off = rdEnd
	}
	return "", q
}

type clientStat struct {
	Queries uint32    `json:"queries"`
	Blocked uint32    `json:"blocked"`
	Last    time.Time `json:"last"`
}

type clientView struct {
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
	Mode string `json:"mode,omitempty"` // this device's own filter mode ("" = the default)
	clientStat
}

// deviceNames maps address -> name from the DHCP reservations (MAC,IP,name) and the lease file (expiry mac ip hostname id); reservations win.
func deviceNames(leases, hosts string) map[string]string {
	m := map[string]string{}
	if f, err := os.Open(leases); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if p := strings.Fields(sc.Text()); len(p) >= 4 && p[3] != "*" && net.ParseIP(p[2]) != nil {
				m[p[2]] = p[3]
			}
		}
		f.Close()
	}
	if f, err := os.Open(hosts); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(l, "#") {
				continue
			}
			if p := strings.Split(l, ","); len(p) >= 3 && net.ParseIP(p[1]) != nil {
				m[p[1]] = p[2]
			}
		}
		f.Close()
	}
	return m
}

func sortClients(v []clientView) {
	sort.Slice(v, func(i, j int) bool {
		return v[i].Queries > v[j].Queries || (v[i].Queries == v[j].Queries && v[i].IP < v[j].IP)
	})
}
