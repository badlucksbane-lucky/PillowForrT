package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func mkQuery(name string, qtype uint16, id uint16, rd bool) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], id)
	if rd {
		binary.BigEndian.PutUint16(b[2:4], 0x0100)
	}
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1) // name terminator, QTYPE, QCLASS IN
	return b
}

func TestParseQuery(t *testing.T) {
	q, err := parseQuery(mkQuery("Ads.Example.COM", qtA, 0xBEEF, true))
	if err != nil || q.Name != "ads.example.com" || q.Type != qtA || q.Class != 1 || q.ID != 0xBEEF || q.Flags&0x0100 == 0 {
		t.Fatalf("parse: %+v %v", q, err)
	}
	full := mkQuery("a.b.example.org", qtAAAA, 1, true)
	q, _ = parseQuery(full)
	if q.QEnd != len(full) {
		t.Fatalf("QEnd %d want %d", q.QEnd, len(full))
	}
	for n := 0; n < len(full); n++ { // every truncation must fail cleanly, never panic
		if _, err := parseQuery(full[:n]); err == nil {
			t.Fatalf("truncated to %d bytes parsed without error", n)
		}
	}
	resp := append([]byte(nil), full...)
	resp[2] |= 0x80 // QR: this is a response
	if _, err := parseQuery(resp); err == nil {
		t.Fatal("a response was accepted as a query")
	}
	op := append([]byte(nil), full...)
	op[2] |= 0x28 // opcode 5
	if _, err := parseQuery(op); err == nil {
		t.Fatal("a non-QUERY opcode was accepted")
	}
	two := append([]byte(nil), full...)
	two[5] = 2
	if _, err := parseQuery(two); err == nil {
		t.Fatal("two questions accepted")
	}
	ptr := append([]byte(nil), full[:12]...)
	ptr = append(ptr, 0xC0, 0x0C, 0, 1, 0, 1) // a compression pointer in a question
	if _, err := parseQuery(ptr); err == nil {
		t.Fatal("pointer in question accepted")
	}
}

func TestBuildBlocked(t *testing.T) {
	for _, tc := range []struct {
		typ  uint16
		want int // answer count
		rd   int
	}{{qtA, 1, 4}, {qtAAAA, 1, 16}, {65, 0, 0}, {16, 0, 0}} {
		qb := mkQuery("ads.example.com", tc.typ, 0x1234, true)
		q, _ := parseQuery(qb)
		r := buildBlocked(qb, q, 45)
		if binary.BigEndian.Uint16(r[0:2]) != 0x1234 || r[2]&0x80 == 0 || r[2]&0x01 == 0 || r[3]&0x80 == 0 || rcodeOf(r) != 0 {
			t.Fatalf("type %d header wrong: % x", tc.typ, r[:12])
		}
		if !bytes.Equal(r[12:q.QEnd], qb[12:q.QEnd]) {
			t.Fatal("question not echoed")
		}
		recs, an, err := records(r)
		if err != nil || an != tc.want || len(recs) != tc.want {
			t.Fatalf("type %d: answers %d recs %d err %v", tc.typ, an, len(recs), err)
		}
		if tc.want == 1 {
			if binary.BigEndian.Uint32(r[recs[0].ttlOff:]) != 45 {
				t.Fatal("ttl not set")
			}
			rdata := r[recs[0].ttlOff+6:]
			if len(rdata) != tc.rd || strings.Trim(string(rdata), "\x00") != "" {
				t.Fatalf("rdata not all zero / wrong length: % x", rdata)
			}
		}
	}
	// RD not set in the query -> not set in the answer
	qb := mkQuery("x.example.com", qtA, 7, false)
	q, _ := parseQuery(qb)
	if r := buildBlocked(qb, q, 30); r[2]&0x01 != 0 {
		t.Fatal("RD echoed when the query had none")
	}
}

// response with a compression pointer, two A records and an OPT record whose "TTL" holds flags
func sampleResponse() []byte {
	qb := mkQuery("example.com", qtA, 9, true)
	q, _ := parseQuery(qb)
	r := respHeader(q, 0, 2)
	r = append(r, qb[12:q.QEnd]...)
	for _, ttl := range []uint32{300, 60} {
		rec := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4}
		binary.BigEndian.PutUint32(rec[6:10], ttl)
		r = append(r, rec...)
	}
	binary.BigEndian.PutUint16(r[10:12], 1) // one additional: OPT
	r = append(r, 0, 0, byte(qtOPT), 0x10, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0)
	return r
}

func TestTTLWalk(t *testing.T) {
	r := sampleResponse()
	if m, ok := minTTL(r); !ok || m != 60 {
		t.Fatalf("minTTL %d %v (the OPT field must be ignored)", m, ok)
	}
	c := append([]byte(nil), r...)
	decrementTTL(c, 30)
	recs, _, _ := records(c)
	if a, b := binary.BigEndian.Uint32(c[recs[0].ttlOff:]), binary.BigEndian.Uint32(c[recs[1].ttlOff:]); a != 270 || b != 30 {
		t.Fatalf("after 30s: %d %d", a, b)
	}
	if binary.BigEndian.Uint32(c[recs[2].ttlOff:]) != 0xFFFFFFFF {
		t.Fatal("the OPT record was modified")
	}
	decrementTTL(c, 1000)
	if a := binary.BigEndian.Uint32(c[recs[0].ttlOff:]); a != 1 {
		t.Fatalf("TTL must floor at 1, got %d", a)
	}
	for n := 0; n < len(r); n++ { // truncated responses: error or ok, never a panic
		minTTL(r[:n])
		decrementTTL(append([]byte(nil), r[:n]...), 5)
	}
	if _, ok := minTTL(buildRcode(mkQuery("a.b", qtA, 1, true), dnsQuery{ID: 1, QEnd: 0}, 2)); ok {
		t.Fatal("no records should mean no TTL")
	}
}

func TestRcodeBuilders(t *testing.T) {
	qb := mkQuery("a.example.com", qtA, 5, true)
	q, _ := parseQuery(qb)
	if r := buildRcode(qb, q, 2); rcodeOf(r) != 2 || binary.BigEndian.Uint16(r[0:2]) != 5 || !bytes.Equal(r[12:], qb[12:q.QEnd]) {
		t.Fatalf("servfail: % x", r)
	}
	if r := buildRcode([]byte{1, 2, 3, 4}, dnsQuery{ID: 0x4242}, 1); len(r) != 12 || rcodeOf(r) != 1 || binary.BigEndian.Uint16(r[0:2]) != 0x4242 {
		t.Fatalf("formerr: % x", r)
	}
}
