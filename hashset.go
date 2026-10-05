package main

import (
	"hash/maphash"
	"sort"
)

// hashSet is a read-only set of domain names kept as sorted 64-bit hashes: 8 bytes an entry, where a map[string]struct{}
// costs about 75 (string header, the bytes in their own allocation, bucket overhead). The Orbic has ~75 MB and the two block
// lists hold ~130k names. A false "yes" needs two names with the same 64-bit hash (about 1 in 10^14 per lookup at this size),
// and the seed is random per process, so nobody can craft a name that collides with a listed one.
type hashSet []uint64

var hashSeed = maphash.MakeSeed()

func hashName(s string) uint64 { return maphash.String(hashSeed, s) }

// sealHashSet sorts and de-duplicates a slice of name hashes into a set (the streaming loaders build the raw slice themselves).
func sealHashSet(h hashSet) hashSet {
	sort.Slice(h, func(i, j int) bool { return h[i] < h[j] })
	out := h[:0]
	for i, v := range h {
		if i == 0 || v != h[i-1] {
			out = append(out, v)
		}
	}
	return out[:len(out):len(out)]
}

// newHashSet builds the set from names (duplicates are fine).
func newHashSet(names []string) hashSet {
	h := make(hashSet, len(names))
	for i, n := range names {
		h[i] = hashName(n)
	}
	sort.Slice(h, func(i, j int) bool { return h[i] < h[j] })
	out := h[:0]
	for i, v := range h {
		if i == 0 || v != h[i-1] {
			out = append(out, v)
		}
	}
	return out[:len(out):len(out)]
}

func (h hashSet) has(name string) bool {
	v := hashName(name)
	i := sort.Search(len(h), func(i int) bool { return h[i] >= v })
	return i < len(h) && h[i] == v
}
