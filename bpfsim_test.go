package main

import "encoding/binary"

// ipv4Frame builds an Ethernet+IPv4 frame with the given protocol, TTL, addresses and transport header bytes.
func ipv4Frame(srcMAC []byte, proto byte, ttl byte, src, dst [4]byte, transport []byte) []byte {
	f := make([]byte, 14+20)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], uint16(20+len(transport)))
	f[22] = ttl
	f[23] = proto
	copy(f[26:30], src[:])
	copy(f[30:34], dst[:])
	return append(f, transport...)
}

func tcpHdr(sport, dport uint16, flags byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	h[12] = 0x50
	h[13] = flags
	return h
}

func udpHdr(sport, dport uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], 8)
	return h
}
