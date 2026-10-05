package main

// LAN IPv6 switch (0.41.0). Why: a browser's WebRTC lists every address on the device's own interface, so a device exiting through Mullvad still showed its
// real carrier IPv6 address (the tunnel carries IPv4 only and its IPv6 is refused, but the address itself sits on the phone). The only router-side cure is for the device not to have one.
// "Off" means three things:
//   - `radish` (the stock program that relays the carrier's router advertisements onto bridge0) is muzzled: ip6tables OUTPUT drops type-134 on bridge0 (chain HS_LANV6_RA);
//   - LAN IPv6 headed for the cellular side is refused (chain HS_LANV6_FWD), so anything still holding an address falls straight back to IPv4;
//   - a one-time "withdraw" advertisement goes out to the LAN (and again every 5 minutes while off): router lifetime 0 and the carrier prefix with preferred = valid = 0. Hosts
//     deprecate the address at once and drop it within 2 hours (Linux and Android ignore a valid lifetime below 2 h; a Wi-Fi reconnect drops it immediately). The packet carries
//     SO_MARK 0x4e, which the drop rule lets through.
// The Orbic's own IPv6 (its cellular side, the porch relay, the onion door) is not touched. OFF IS THE DEFAULT (): LAN IPv6 is on only while the flag file
// /data/proxy/lanv6.on exists, so a wiped /data, a restore or a first boot comes up with it off. On again: the rules go within 20 seconds and radish's next carrier
// advertisement (a few minutes, or a device's solicitation) hands the prefix back. (0.41.0 used lanv6.off with the opposite meaning; its file is simply ignored now.)

import (
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const lanV6Mark = 0x4e

type lanV6 struct {
	mu       sync.Mutex
	flag     string
	apply    func(off bool) error
	withdraw func() error // sends the withdraw advertisement
	off      bool
	checked  time.Time
	lastSend time.Time
	now      func() time.Time
}

func defaultLanV6() *lanV6 {
	return &lanV6{flag: *lanV6Flag, now: time.Now, apply: applyLanV6Rules, withdraw: sendWithdrawRA}
}

func (s *lanV6) Off() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.checked) > time.Second {
		_, err := os.Stat(s.flag)
		s.off, s.checked = err != nil, s.now() // flag present = on
	}
	return s.off
}

// Set records the choice, sends the withdraw advertisement BEFORE the drop rule goes in (belt and braces beside the mark), then applies the rules.
func (s *lanV6) Set(off bool) error {
	s.mu.Lock()
	var err error
	if !off {
		err = os.WriteFile(s.flag, []byte("LAN IPv6 is switched on: remove this file to switch it off (off is the default)\n"), 0o644)
	} else if e := os.Remove(s.flag); e != nil && !os.IsNotExist(e) {
		err = e
	}
	s.off, s.checked = off, s.now()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	var msgs []string
	if off {
		if e := s.sendWithdraw(); e != nil {
			msgs = append(msgs, "withdraw advertisement: "+e.Error())
		}
	}
	if e := s.apply(off); e != nil {
		msgs = append(msgs, e.Error())
	}
	if len(msgs) > 0 {
		return errors.New("saved, but " + strings.Join(msgs, "; ") + " (rules are re-applied within 20 seconds)")
	}
	return nil
}

func (s *lanV6) sendWithdraw() error {
	// two copies a second apart: a sleeping Wi-Fi client can miss one multicast
	err := s.withdraw()
	time.Sleep(time.Second)
	if e := s.withdraw(); err == nil {
		err = e
	}
	s.mu.Lock()
	s.lastSend = s.now()
	s.mu.Unlock()
	return err
}

func (s *lanV6) Reconcile() {
	off := s.Off()
	if err := s.apply(off); err != nil {
		log.Printf("LAN IPv6 switch: %v", err)
	}
	s.mu.Lock()
	due := off && s.now().Sub(s.lastSend) > 5*time.Minute
	s.mu.Unlock()
	if due {
		if err := s.sendWithdraw(); err != nil {
			log.Printf("LAN IPv6 withdraw: %v", err)
		}
	}
}

func (s *lanV6) Run() {
	for {
		s.Reconcile()
		time.Sleep(20 * time.Second)
	}
}

func applyLanV6Rules(off bool) error {
	if out, err := run("sh", "-c", lanV6Script(off)); err != nil {
		return errors.New("firewall: " + strings.TrimSpace(out))
	}
	return nil
}

func lanV6Script(off bool) string {
	const ra = "-o bridge0 -p icmpv6 --icmpv6-type 134 -j DROP"
	const fwd = "-i bridge0 -o rmnet_data+ -j REJECT --reject-with icmp6-port-unreachable"
	var b strings.Builder
	b.WriteString("ip6tables -N HS_LANV6_RA 2>/dev/null\nip6tables -N HS_LANV6_FWD 2>/dev/null\n")
	if off {
		b.WriteString("ip6tables -C HS_LANV6_RA -m mark --mark 0x4e -j RETURN 2>/dev/null && ip6tables -C HS_LANV6_RA " + ra + " 2>/dev/null || " +
			"{ ip6tables -F HS_LANV6_RA && ip6tables -A HS_LANV6_RA -m mark --mark 0x4e -j RETURN && ip6tables -A HS_LANV6_RA " + ra + "; }\n")
		b.WriteString("ip6tables -C HS_LANV6_FWD " + fwd + " 2>/dev/null || { ip6tables -F HS_LANV6_FWD && ip6tables -A HS_LANV6_FWD " + fwd + "; }\n")
		b.WriteString("ip6tables -C OUTPUT -j HS_LANV6_RA 2>/dev/null || ip6tables -I OUTPUT 1 -j HS_LANV6_RA\n")
		b.WriteString("ip6tables -C FORWARD -j HS_LANV6_FWD 2>/dev/null || ip6tables -I FORWARD 1 -j HS_LANV6_FWD\n")
	} else {
		b.WriteString("while ip6tables -D OUTPUT -j HS_LANV6_RA 2>/dev/null; do :; done\nwhile ip6tables -D FORWARD -j HS_LANV6_FWD 2>/dev/null; do :; done\n")
		b.WriteString("ip6tables -F HS_LANV6_RA\nip6tables -F HS_LANV6_FWD\n")
	}
	return b.String()
}

// buildWithdrawRA is the ICMPv6 router advertisement body (the kernel adds the IPv6 header and the checksum on a raw ICMPv6 socket): router lifetime 0, a source link-layer
// address option, and the prefix with L and A set and both lifetimes 0.
func buildWithdrawRA(mac net.HardwareAddr, prefix net.IP) []byte {
	p := make([]byte, 0, 56)
	p = append(p, 134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // type, code, checksum, hop limit, flags, router lifetime 0, reachable 0, retrans 0
	if len(mac) == 6 {
		p = append(p, 1, 1)
		p = append(p, mac...)
	}
	p = append(p, 3, 4, 64, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // prefix info: len 64, L|A, valid 0, preferred 0, reserved
	p = append(p, prefix.To16()...)
	return p
}

// carrierPrefix is the /64 radish was advertising: the global address on the cellular interface, masked.
func carrierPrefix() (net.IP, error) {
	ifc, err := net.InterfaceByName("rmnet_data0")
	if err != nil {
		return nil, err
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() {
			return ipn.IP.Mask(net.CIDRMask(64, 128)), nil
		}
	}
	return nil, errors.New("no global IPv6 address on the cellular interface (nothing to withdraw)")
}

func sendWithdrawRA() error {
	prefix, err := carrierPrefix()
	if err != nil {
		return err
	}
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	var ll net.IP
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.IsLinkLocalUnicast() {
			ll = ipn.IP
		}
	}
	if ll == nil {
		return errors.New("bridge0 has no link-local address")
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	for _, o := range []struct{ lvl, opt, val int }{
		{syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255}, {syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, 255},
		{syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifc.Index}, {syscall.SOL_SOCKET, syscall.SO_MARK, lanV6Mark},
	} {
		if err := syscall.SetsockoptInt(fd, o.lvl, o.opt, o.val); err != nil {
			return err
		}
	}
	src := &syscall.SockaddrInet6{ZoneId: uint32(ifc.Index)}
	copy(src.Addr[:], ll.To16())
	if err := syscall.Bind(fd, src); err != nil {
		return err
	}
	dst := &syscall.SockaddrInet6{ZoneId: uint32(ifc.Index)}
	copy(dst.Addr[:], net.ParseIP("ff02::1").To16())
	return syscall.Sendto(fd, buildWithdrawRA(ifc.HardwareAddr, prefix), 0, dst)
}

type lanV6View struct {
	Off     bool   `json:"off"`
	RulesIn bool   `json:"rules_in_place"`
	Prefix  string `json:"prefix,omitempty"` // the carrier prefix a withdrawal names
}

func (s *lanV6) View() lanV6View {
	v := lanV6View{Off: s.Off()}
	out, _ := run("ip6tables", "-S", "OUTPUT")
	fw, _ := run("ip6tables", "-S", "FORWARD")
	v.RulesIn = strings.Contains(out, "-j HS_LANV6_RA") && strings.Contains(fw, "-j HS_LANV6_FWD")
	if p, err := carrierPrefix(); err == nil {
		v.Prefix = p.String() + "/64"
	}
	return v
}
