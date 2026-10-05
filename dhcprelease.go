package main

// DHCPRELEASE, sent to our own dnsmasq on behalf of a device (a port of dnsmasq's contrib/lease-tools/dhcp_release.c): it makes dnsmasq forget the device's current
// lease, so when the device next asks it is given its reserved address instead of renewing the old one. A phone that simply re-asks for the address it already holds (which is what
// Android does after a Wi-Fi reconnect) never moves to a new reservation otherwise.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"
)

const lanGateway = "192.168.1.1"

// buildRelease makes the 548-byte BOOTP/DHCP message the stock tool sends.
func buildRelease(ip, mac, server string) ([]byte, error) {
	cip := net.ParseIP(ip).To4()
	sip := net.ParseIP(server).To4()
	hw, err := net.ParseMAC(mac)
	if cip == nil || sip == nil || err != nil || len(hw) != 6 {
		return nil, errors.New("bad address or MAC for a DHCP release")
	}
	p := make([]byte, 548)
	p[0], p[1], p[2] = 1, 1, 6 // BOOTREQUEST, Ethernet, 6-byte hardware address
	binary.BigEndian.PutUint32(p[4:], uint32(time.Now().UnixNano()))
	copy(p[12:16], cip) // ciaddr: the address being released
	copy(p[28:], hw)    // chaddr
	binary.BigEndian.PutUint32(p[236:], 0x63825363)
	o := p[240:]
	o = append(o[:0], 53, 1, 7)                          // DHCPRELEASE
	o = append(o, 54, 4, sip[0], sip[1], sip[2], sip[3]) // server identifier
	o = append(o, 61, 7, 1)                              // client identifier: type 1 + the MAC, as Android sends it
	o = append(o, hw...)
	o = append(o, 255)
	copy(p[240:], o)
	return p, nil
}

func sendRelease(iface, ip, mac string) error {
	pkt, err := buildRelease(ip, mac, lanGateway)
	if err != nil {
		return err
	}
	d := &net.Dialer{Timeout: 3 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "udp4", lanGateway+":67")
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(pkt)
	return err
}

// currentAddress: the address a MAC is using on the LAN right now (ARP first, then the lease file), "" if unknown.
func currentAddress(mac string) string {
	_, ipOf := lanNames()
	return ipOf[strings.ToLower(mac)]
}
