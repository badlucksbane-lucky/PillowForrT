package main

import (
	"fmt"
	"strings"
	"testing"
)

// conntrackDump builds n lines in the format the box's 3.18 kernel writes to /proc/net/nf_conntrack: mostly LAN-to-internet flows, some local ones.
func conntrackDump(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		src, dst := fmt.Sprintf("192.168.1.%d", 2+i%200), fmt.Sprintf("%d.%d.%d.%d", 20+i%200, i%250, (i/7)%250, 1+i%250)
		if i%10 == 0 {
			dst = "192.168.1.1" // local: not an outbound flow
		}
		if i%3 == 0 {
			fmt.Fprintf(&b, "ipv4     2 udp      17 %d src=%s dst=%s sport=%d dport=%d packets=3 bytes=400 src=%s dst=100.65.1.1 sport=%d dport=%d packets=2 bytes=300 mark=0 secmark=0 use=2\n",
				20+i%100, src, dst, 30000+i, 443, dst, 443, 30000+i)
		} else {
			fmt.Fprintf(&b, "ipv4     2 tcp      6 %d ESTABLISHED src=%s dst=%s sport=%d dport=%d packets=10 bytes=1000 src=%s dst=100.65.1.1 sport=%d dport=%d packets=9 bytes=9000 [ASSURED] mark=0 secmark=0 use=2\n",
				400000+i, src, dst, 40000+i, 443, dst, 443, 40000+i)
		}
	}
	return b.String()
}

func BenchmarkParseConntrack3000(b *testing.B) {
	s := conntrackDump(3000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n := len(parseConntrack(s)); n < 2000 {
			b.Fatal(n)
		}
	}
}

func BenchmarkScanProcsRealProc(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		comms, _, _ := scanProcs("/proc")
		if len(comms) == 0 {
			b.Fatal("no processes")
		}
	}
}
