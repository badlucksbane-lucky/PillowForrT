package main

// One device, many addresses. A phone asks DNS over IPv4 and over IPv6 (the box advertises itself as DNS on both), so the same device would show up
// twice and an IPv4-keyed rule would miss its IPv6 queries. Both are tied together by the device's MAC address: the ARP table gives MAC -> IPv4, the
// IPv6 neighbour table gives IPv6 -> MAC. canonical() turns an IPv6 client address into the device's IPv4 one when both are known.

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type neighbours struct {
	mu   sync.Mutex
	at   time.Time
	ttl  time.Duration
	mac4 map[string]string // MAC -> IPv4
	v6   map[string]string // IPv6 -> MAC
	arp  func() string     // contents of the ARP table
	ndp  func() string     // output of `ip -6 neigh`
}

func newNeighbours() *neighbours {
	return &neighbours{ttl: 10 * time.Second,
		arp: func() string { b, _ := os.ReadFile(filepath.Join(*procDir, "net/arp")); return string(b) },
		ndp: func() string {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, "ip", "-6", "neigh", "show").Output()
			return string(out)
		}}
}

func parseARP(s string) map[string]string {
	m := map[string]string{}
	for i, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if i > 0 && len(f) >= 4 && f[2] != "0x0" && f[3] != "00:00:00:00:00:00" && net.ParseIP(f[0]) != nil {
			m[strings.ToLower(f[3])] = f[0]
		}
	}
	return m
}

// parseNDP reads `ip -6 neigh` lines: "<addr> dev bridge0 lladdr <mac> REACHABLE".
func parseNDP(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				if ip := net.ParseIP(f[0]); ip != nil {
					m[ip.String()] = strings.ToLower(f[i+1])
				}
				break
			}
		}
	}
	return m
}

// canonical maps an IPv6 client address to its device's IPv4 address; anything it cannot place is returned unchanged.
func (n *neighbours) canonical(ip string) string {
	if !strings.Contains(ip, ":") {
		return ip
	}
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	key := p.String()
	n.mu.Lock()
	defer n.mu.Unlock()
	if mac, ok := n.v6[key]; ok {
		if v4, ok := n.mac4[mac]; ok {
			return v4
		}
	}
	if time.Since(n.at) > n.ttl { // look again, at most once per ttl
		n.mac4, n.v6, n.at = parseARP(n.arp()), parseNDP(n.ndp()), time.Now()
		if mac, ok := n.v6[key]; ok {
			if v4, ok := n.mac4[mac]; ok {
				return v4
			}
		}
	}
	return ip
}
