package main

// Minimal DNS wire handling: only what a filtering stub needs (no external packages: the build is offline).
// Parse a query's question, build a "blocked" answer, patch ids, and walk resource records to read or decrement TTLs.

import (
	"encoding/binary"
	"errors"
	"strings"
)

const (
	qtA     = 1
	qtAAAA  = 28
	qtOPT   = 41
	qclassI = 1
)

var errShort = errors.New("dns: short or malformed message")

type dnsQuery struct {
	ID    uint16
	Flags uint16
	Name  string // lower-case, no trailing dot
	Type  uint16
	Class uint16
	QEnd  int // offset just after the question section
}

// skipName returns the offset just after the (possibly compressed) name starting at off.
func skipName(b []byte, off int) (int, error) {
	for hops := 0; hops < 128; hops++ {
		if off >= len(b) {
			return 0, errShort
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return 0, errShort
			}
			return off + 2, nil // a pointer ends the name
		case l&0xC0 != 0:
			return 0, errShort
		default:
			off += 1 + l
		}
	}
	return 0, errShort
}

// parseQuery reads the header and the single question of a client query. Compression pointers are not valid in a question.
func parseQuery(b []byte) (dnsQuery, error) {
	var q dnsQuery
	if len(b) < 12 {
		return q, errShort
	}
	q.ID = binary.BigEndian.Uint16(b[0:2])
	q.Flags = binary.BigEndian.Uint16(b[2:4])
	if q.Flags&0x8000 != 0 || (q.Flags>>11)&0xF != 0 { // a response, or not a standard QUERY
		return q, errors.New("dns: not a standard query")
	}
	if binary.BigEndian.Uint16(b[4:6]) != 1 {
		return q, errors.New("dns: expected exactly one question")
	}
	var sb strings.Builder
	off := 12
	for {
		if off >= len(b) {
			return q, errShort
		}
		l := int(b[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 || off+1+l > len(b) {
			return q, errShort
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range b[off+1 : off+1+l] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			sb.WriteByte(c)
		}
		off += 1 + l
		if sb.Len() > 253 {
			return q, errShort
		}
	}
	if off+4 > len(b) {
		return q, errShort
	}
	q.Name = sb.String()
	q.Type = binary.BigEndian.Uint16(b[off : off+2])
	q.Class = binary.BigEndian.Uint16(b[off+2 : off+4])
	q.QEnd = off + 4
	return q, nil
}

func setID(b []byte, id uint16) {
	if len(b) >= 2 {
		binary.BigEndian.PutUint16(b[0:2], id)
	}
}

// header makes a response header for query q with the given rcode and answer count; RD is echoed, RA set.
func respHeader(q dnsQuery, rcode, ancount int) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], q.ID)
	binary.BigEndian.PutUint16(h[2:4], 0x8000|(q.Flags&0x0100)|0x0080|uint16(rcode&0xF))
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], uint16(ancount))
	return h
}

// buildBlocked answers a blocked name: A -> 0.0.0.0, AAAA -> ::, anything else -> NOERROR with no data. ttl is how long clients may keep it.
func buildBlocked(query []byte, q dnsQuery, ttl uint32) []byte {
	an := 0
	if q.Type == qtA || q.Type == qtAAAA {
		an = 1
	}
	out := append(respHeader(q, 0, an), query[12:q.QEnd]...)
	if an == 1 {
		rdlen := 4
		if q.Type == qtAAAA {
			rdlen = 16
		}
		rr := make([]byte, 12+rdlen)
		rr[0], rr[1] = 0xC0, 0x0C // pointer to the question name
		binary.BigEndian.PutUint16(rr[2:4], q.Type)
		binary.BigEndian.PutUint16(rr[4:6], qclassI)
		binary.BigEndian.PutUint32(rr[6:10], ttl)
		binary.BigEndian.PutUint16(rr[10:12], uint16(rdlen))
		out = append(out, rr...) // rdata is all zero
	}
	return out
}

func buildRcode(query []byte, q dnsQuery, rcode int) []byte {
	end := q.QEnd
	if end == 0 || end > len(query) {
		end = len(query)
	}
	out := respHeader(q, rcode, 0)
	if q.QEnd != 0 {
		out = append(out, query[12:end]...)
	} else {
		binary.BigEndian.PutUint16(out[4:6], 0)
	}
	return out
}

type rr struct {
	typ    uint16
	ttlOff int
}

// records lists every resource record of a response (answer, authority, additional) with where its TTL field sits.
func records(b []byte) ([]rr, int, error) {
	if len(b) < 12 {
		return nil, 0, errShort
	}
	off := 12
	for i := 0; i < int(binary.BigEndian.Uint16(b[4:6])); i++ {
		n, err := skipName(b, off)
		if err != nil || n+4 > len(b) {
			return nil, 0, errShort
		}
		off = n + 4
	}
	total := int(binary.BigEndian.Uint16(b[6:8])) + int(binary.BigEndian.Uint16(b[8:10])) + int(binary.BigEndian.Uint16(b[10:12]))
	var out []rr
	for i := 0; i < total; i++ {
		n, err := skipName(b, off)
		if err != nil || n+10 > len(b) {
			return nil, 0, errShort
		}
		rdlen := int(binary.BigEndian.Uint16(b[n+8 : n+10]))
		if n+10+rdlen > len(b) {
			return nil, 0, errShort
		}
		out = append(out, rr{typ: binary.BigEndian.Uint16(b[n : n+2]), ttlOff: n + 4})
		off = n + 10 + rdlen
	}
	return out, int(binary.BigEndian.Uint16(b[6:8])), nil
}

// minTTL is the smallest TTL among the real records (OPT carries flags in that field, so it is skipped); ok is false when there are none.
func minTTL(b []byte) (uint32, bool) {
	recs, _, err := records(b)
	if err != nil {
		return 0, false
	}
	var min uint32
	found := false
	for _, r := range recs {
		if r.typ == qtOPT {
			continue
		}
		t := binary.BigEndian.Uint32(b[r.ttlOff : r.ttlOff+4])
		if !found || t < min {
			min, found = t, true
		}
	}
	return min, found
}

// decrementTTL lowers every real record's TTL by elapsed seconds (not below 1), in place.
func decrementTTL(b []byte, elapsed uint32) {
	recs, _, err := records(b)
	if err != nil {
		return
	}
	for _, r := range recs {
		if r.typ == qtOPT {
			continue
		}
		t := binary.BigEndian.Uint32(b[r.ttlOff : r.ttlOff+4])
		if t > elapsed+1 {
			t -= elapsed
		} else {
			t = 1
		}
		binary.BigEndian.PutUint32(b[r.ttlOff:r.ttlOff+4], t)
	}
}

func rcodeOf(b []byte) int {
	if len(b) < 4 {
		return 2
	}
	return int(b[3] & 0xF)
}
