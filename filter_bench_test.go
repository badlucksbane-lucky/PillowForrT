package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// benchFilter loads the box's real lists from $FILTER_BENCH_DIR (a copy of /data/dnsfilter); the benchmark is skipped without it.
func benchFilter(b *testing.B) *Filter {
	dir := os.Getenv("FILTER_BENCH_DIR")
	if dir == "" {
		b.Skip("set FILTER_BENCH_DIR to a copy of /data/dnsfilter")
	}
	f := NewFilter(dir)
	f.Load()
	if f.TotalEntries() < 1_000_000 {
		b.Fatalf("only %d names loaded", f.TotalEntries())
	}
	return f
}

// queryNames: names a house asks for, none on a list (the common case: every list is searched in full), and a few that are.
func queryNames(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			out = append(out, fmt.Sprintf("www.site%d.example.com", i))
		case 1:
			out = append(out, fmt.Sprintf("api.v%d.service-%d.co.uk", i%9, i))
		case 2:
			out = append(out, fmt.Sprintf("cdn%d.assets.shop%d.net", i%5, i))
		default:
			out = append(out, fmt.Sprintf("a.b.c.d%d.example.org", i))
		}
	}
	return out
}

func BenchmarkFilterMatchUnlisted(b *testing.B) {
	f := benchFilter(b)
	names := queryNames(2000)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if blocked, _ := f.MatchFor("192.168.1.40", names[i%len(names)], now); blocked {
			b.Fatal("unlisted name blocked")
		}
	}
}

func BenchmarkFilterMatchStrictUnlisted(b *testing.B) { // the device on "strict" searches every downloaded list
	f := benchFilter(b)
	f.SetDeviceMode("192.168.1.41", "strict")
	names := queryNames(2000)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.MatchFor("192.168.1.41", names[i%len(names)], now)
	}
}
