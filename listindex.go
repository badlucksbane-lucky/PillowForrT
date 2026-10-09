package main

// All the block lists in one lookup. A name that is on several lists is stored once, with a mask of which lists have it (bit i = defaultLists[i]); the table is sorted by the
// name's 64-bit hash, with a bucket index on the hash's top bits so that a probe is one jump and a short scan of a few neighbouring entries instead of a binary search over
// half a million. A query costs one probe per suffix level of the name (3 or 4), not one search per list per level (13 lists times that). Cost per name: 8 bytes of hash, 2 of
// mask, and about 0.7 of bucket index. The keys are the name's 64-bit hash with its low 4 bits cleared (60 bits): a false match needs two names to share 60 bits, about 1 in 10^12 a
// probe at this size, and the seed is random per process (see hashset.go). The low 4 bits are free to carry a list's number while the table is being built.

import (
	"math/bits"
	"slices"
	"strings"
)

type listIndex struct {
	keys   []uint64   // sorted, unique
	masks  []uint16   // masks[i]: the lists that have keys[i]
	starts []uint32   // keys[starts[b]:starts[b+1]] are the keys whose top bits are b
	shift  uint       // 64 - the number of bucket bits
	over   *listIndex // names that a list update added after the table was built (small; see withList); nil when there are none
}

// overlayDiv: the overlay is folded back into the table when it holds more than a 1/overlayDiv of its names. A variable so that tests can force either path.
var overlayDiv = 8

var (
	listBit    = map[string]int{} // list name -> bit
	wildMask   uint16             // the lists whose entries also cover every subdomain
	allMask    uint16
	legacyMask = map[string]uint16{} // the first version's modes, as masks
)

func init() {
	if len(defaultLists) > 16 {
		panic("the list index keeps one bit a list in a uint16: widen listIndex.masks")
	}
	for i, sp := range defaultLists {
		listBit[sp.Name] = i
		allMask |= 1 << i
		if sp.Wildcard {
			wildMask |= 1 << i
		}
	}
	for mode, names := range legacyModes {
		for _, n := range names {
			legacyMask[mode] |= 1 << listBit[n]
		}
	}
}

const keyMask = ^uint64(0xF) // the key of a hash: its low 4 bits are not part of it

// lookup returns the lists that have this hash.
func (ix *listIndex) lookup(h uint64) uint16 {
	if ix == nil {
		return 0
	}
	h &= keyMask
	m := uint16(0)
	if i := ix.find(h); i >= 0 {
		m = ix.masks[i]
	}
	if ix.over != nil {
		if i := ix.over.find(h); i >= 0 {
			m |= ix.over.masks[i]
		}
	}
	return m
}

// find returns the position of key k (already cleared of its low bits) in this table, not in its overlay, or -1.
func (ix *listIndex) find(k uint64) int {
	if len(ix.keys) == 0 {
		return -1
	}
	b := k >> ix.shift
	for i, end := ix.starts[b], ix.starts[b+1]; i < end; i++ {
		if v := ix.keys[i]; v == k {
			return int(i)
		} else if v > k {
			break // sorted within the bucket
		}
	}
	return -1
}

// match returns which of the lists in `only` block name: those that have the name itself, and the wildcard ones that have it or any parent that still has a dot (never a bare TLD).
// The caller takes the first list in the catalog's order, which is the lowest bit.
func (ix *listIndex) match(name string, only uint16) uint16 {
	if ix == nil || only == 0 {
		return 0
	}
	var hit uint16
	s, full := name, true
	for {
		m := ix.lookup(hashName(s)) & only
		if !full {
			m &= wildMask
		}
		hit |= m
		full = false
		i := strings.IndexByte(s, '.')
		if i < 0 || strings.IndexByte(s[i+1:], '.') < 0 {
			return hit
		}
		s = s[i+1:]
	}
}

// ---- building ----

// mergeSrc is one sorted input of a build: either another index (masks given; the bits in clear are dropped from it) or one list's hashes (every one gets mask).
type mergeSrc struct {
	keys  []uint64
	masks []uint16
	mask  uint16
	clear uint16
	trunc bool // the keys are full hashes: compare them as keys (low 4 bits cleared; the order is kept, equal neighbours merge)
}

func (s *mergeSrc) key(i int) uint64 {
	if s.trunc {
		return s.keys[i] & keyMask
	}
	return s.keys[i]
}

// buildIndex merges sorted inputs into an index. A name whose mask ends up empty (its only lists were cleared) is dropped.
func buildIndex(srcs []mergeSrc) *listIndex {
	total := 0
	for _, s := range srcs {
		total += len(s.keys)
	}
	keys, masks := make([]uint64, 0, total), make([]uint16, 0, total)
	pos := make([]int, len(srcs))
	var at [17]int // the inputs whose next key is the smallest one
	for {
		n, min := 0, ^uint64(0)
		for i := range srcs {
			if pos[i] >= len(srcs[i].keys) {
				continue
			}
			if k := srcs[i].key(pos[i]); n == 0 || k < min {
				min, n, at[0] = k, 1, i
			} else if k == min {
				at[n] = i
				n++
			}
		}
		if n == 0 {
			break
		}
		var m uint16
		for _, i := range at[:n] {
			if s := &srcs[i]; s.masks != nil {
				m |= s.masks[pos[i]] &^ s.clear
			} else {
				m |= s.mask
			}
			pos[i]++
		}
		if m == 0 {
			continue
		}
		if l := len(keys) - 1; l >= 0 && keys[l] == min { // two hashes of one source that differ only in the cleared bits
			masks[l] |= m
		} else {
			keys, masks = append(keys, min), append(masks, m)
		}
	}
	if cap(keys) > len(keys)+len(keys)/16 { // cut to size: the inputs overlap, so the upper bound was too generous
		keys, masks = append([]uint64(nil), keys...), append([]uint16(nil), masks...)
	}
	return finishIndex(keys, masks)
}

// finishIndex adds the bucket table to sorted unique keys with their masks.
func finishIndex(keys []uint64, masks []uint16) *listIndex {
	if len(keys) == 0 {
		return &listIndex{}
	}
	b := bits.Len(uint(len(keys) / 8))
	b = min(max(b, 8), 22)
	ix := &listIndex{keys: keys, masks: masks, shift: uint(64 - b), starts: make([]uint32, 1<<b+1)}
	for _, k := range keys {
		ix.starts[(k>>ix.shift)+1]++
	}
	for i := 1; i < len(ix.starts); i++ {
		ix.starts[i] += ix.starts[i-1]
	}
	return ix
}

// tagRecord is a hash with a list's number in its low 4 bits: one word that carries both while a table is built from the lists' files.
func tagRecord(h uint64, bit int) uint64 { return h&keyMask | uint64(bit) }

// indexFromRecords builds the table from tagged records, in the memory the records are in: sort them, then walk them once to count the distinct keys and once more to write
// each key (and the OR of its lists' bits) over the front of the same array. The peak is the records plus the masks, not the records plus a second copy of everything.
// recs is consumed.
func indexFromRecords(recs []uint64) *listIndex {
	if len(recs) == 0 {
		return &listIndex{}
	}
	slices.Sort(recs)
	distinct := 1
	for i := 1; i < len(recs); i++ {
		if recs[i]&keyMask != recs[i-1]&keyMask {
			distinct++
		}
	}
	masks := make([]uint16, distinct)
	w := 0
	masks[0] = 1 << (recs[0] & 0xF)
	recs[0] &= keyMask
	for i := 1; i < len(recs); i++ {
		k, bit := recs[i]&keyMask, uint16(1)<<(recs[i]&0xF)
		if k != recs[w] {
			w++
			recs[w] = k
		}
		masks[w] |= bit
	}
	return finishIndex(recs[:w+1:w+1], masks)
}

// listCounts says how many names each list has in the table.
func (ix *listIndex) listCounts() (n [16]int) {
	for t := ix; t != nil; t = t.over {
		for _, m := range t.masks {
			for ; m != 0; m &= m - 1 {
				n[bits.TrailingZeros16(m)]++
			}
		}
	}
	return
}

// src lists the sorted inputs that make up this index (its table and its overlay), with the bits in clear dropped.
func (ix *listIndex) src(clear uint16) []mergeSrc {
	if ix == nil {
		return nil
	}
	var out []mergeSrc
	if len(ix.keys) > 0 {
		out = append(out, mergeSrc{keys: ix.keys, masks: ix.masks, clear: clear})
	}
	if ix.over != nil && len(ix.over.keys) > 0 {
		out = append(out, mergeSrc{keys: ix.over.keys, masks: ix.over.masks, clear: clear})
	}
	return out
}

// withList returns a new index in which list `bit` is exactly `set` (nil removes it); the others are as they were.
//
// Writing a whole new table for it would take twice the table's memory for a moment (a third of the daemon's budget, for the daily update). Instead the new index SHARES the old
// one's keys and bucket table, which do not change, and gets a copy of the masks (2 bytes a name) with the list's bit cleared and then set for every name of the new copy that is
// in the table already. Names the table has not got go into a small overlay table. A name that left the list stays in the table with an empty mask, which finds nothing.
// When the overlay has grown past a fraction of the table, everything is merged into a fresh table (and the dead names drop out); a restart does the same.
func (ix *listIndex) withList(bit int, set hashSet) *listIndex {
	if ix == nil || len(ix.keys) == 0 {
		return buildIndex(append(ix.src(1<<bit), mergeSrc{keys: set, mask: 1 << bit, trunc: true}))
	}
	one := uint16(1) << bit
	masks := slices.Clone(ix.masks)
	for i := range masks {
		masks[i] &^= one
	}
	var extra []uint64 // names of the new copy that the table has not got: sorted, unique
	for _, h := range set {
		k := h & keyMask
		if i := ix.find(k); i >= 0 {
			masks[i] |= one
		} else if n := len(extra); n == 0 || extra[n-1] != k {
			extra = append(extra, k)
		}
	}
	next := &listIndex{keys: ix.keys, masks: masks, starts: ix.starts, shift: ix.shift}
	var oldOver []mergeSrc
	if ix.over != nil {
		oldOver = []mergeSrc{{keys: ix.over.keys, masks: ix.over.masks, clear: one}}
	}
	if len(extra) > 0 || len(oldOver) > 0 {
		if len(extra) > 0 {
			oldOver = append(oldOver, mergeSrc{keys: extra, mask: one})
		}
		next.over = buildIndex(oldOver)
		if len(next.over.keys) == 0 {
			next.over = nil
		}
	}
	if next.over != nil && len(next.over.keys)*overlayDiv > len(next.keys) {
		return buildIndex(next.src(0)) // fold the overlay in
	}
	return next
}

type listPart struct {
	bit int
	set hashSet
}

// withLists is withList for several lists at once (the start-up load).
func (ix *listIndex) withLists(parts []listPart) *listIndex {
	var clear uint16
	for _, p := range parts {
		clear |= 1 << p.bit
	}
	srcs := ix.src(clear)
	for _, p := range parts {
		if len(p.set) > 0 {
			srcs = append(srcs, mergeSrc{keys: p.set, mask: 1 << p.bit, trunc: true})
		}
	}
	return buildIndex(srcs)
}

// mergeIndexes is the union of two indexes (a name keeps the lists it has in either).
func mergeIndexes(a, b *listIndex) *listIndex {
	return buildIndex(append(a.src(0), b.src(0)...))
}
