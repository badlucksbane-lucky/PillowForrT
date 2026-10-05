package main

// Per-device labels and notes, and wake-on-LAN. A label is how the page names a device (it wins over the DHCP reservation name and the hostname the device announces); a note is
// free text for you ("kitchen bulb, bought 2024"). They are display-only: they never touch DHCP, the firewall or any other page's rules, and they are kept in
// /data/proxy/devnotes.json (0600), included in settings snapshots. Wake-on-LAN sends the standard magic packet (6 x 0xFF, then the MAC 16 times) as a UDP broadcast to ports 9 and
// 7 and as a raw Ethernet frame (type 0x0842) on the LAN bridge; most Wi-Fi devices ignore it (only wired devices and ones set up for wake-on-wireless wake).

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

type devNote struct {
	Label string `json:"label,omitempty"`
	Note  string `json:"note,omitempty"`
}

type devNotes struct {
	mu   sync.Mutex
	path string
}

func defaultDevNotes() *devNotes { return &devNotes{path: *devNotesFile} }

func (d *devNotes) load() map[string]devNote {
	m := map[string]devNote{}
	if b, err := os.ReadFile(d.path); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func (d *devNotes) All() map[string]devNote {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.load()
}

func cleanText(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > max {
		return "", errors.New("is too long")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("contains a control character")
		}
	}
	return s, nil
}

// Set stores a label and note for a MAC; both empty removes the entry.
func (d *devNotes) Set(mac, label, note string) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	l, err := cleanText(label, 40)
	if err != nil {
		return errors.New("the name " + err.Error() + " (40 characters at most, no control characters)")
	}
	n, err := cleanText(note, 200)
	if err != nil {
		return errors.New("the note " + err.Error() + " (200 characters at most, no control characters)")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.load()
	if l == "" && n == "" {
		delete(m, mac)
	} else {
		if _, had := m[mac]; !had && len(m) >= 128 {
			return errors.New("too many labelled devices (128 is the limit)")
		}
		m[mac] = devNote{Label: l, Note: n}
	}
	return d.save(m)
}

func (d *devNotes) save(m map[string]devNote) error {
	b, _ := json.MarshalIndent(m, "", " ")
	return writeFileAtomic(d.path, b, 0o600)
}

// checkAll validates a whole set without storing it.
func (d *devNotes) checkAll(in map[string]devNote) error {
	_, err := cleanNotes(in)
	return err
}

func cleanNotes(in map[string]devNote) (map[string]devNote, error) {
	clean := map[string]devNote{}
	for mac, n := range in {
		mac = strings.ToLower(mac)
		if !macRe.MatchString(mac) {
			return nil, errors.New("not a MAC address: " + mac)
		}
		l, e1 := cleanText(n.Label, 40)
		t, e2 := cleanText(n.Note, 200)
		if e1 != nil || e2 != nil {
			return nil, errors.New("a label or note is not valid")
		}
		if l != "" || t != "" {
			clean[mac] = devNote{Label: l, Note: t}
		}
	}
	if len(clean) > 128 {
		return nil, errors.New("too many labelled devices")
	}
	return clean, nil
}

// Replace swaps everything (a snapshot restore); entries are validated like Set.
func (d *devNotes) Replace(in map[string]devNote) error {
	clean, err := cleanNotes(in)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.save(clean)
}

// ---- wake-on-LAN ----

// magicPacket is the payload every wake-on-LAN receiver looks for.
func magicPacket(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return nil, errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xff)
	}
	for i := 0; i < 16; i++ {
		p = append(p, hw...)
	}
	return p, nil
}

// sendWake sends the magic packet as UDP broadcasts (ports 9 and 7) and as a raw Ethernet frame on the LAN bridge. It reports an error only if nothing at all could be sent.
var sendWake = func(mac string) error {
	p, err := magicPacket(mac)
	if err != nil {
		return err
	}
	sent := 0
	for _, port := range []string{"9", "7"} {
		c, err := net.DialTimeout("udp4", "192.168.1.255:"+port, 2*time.Second)
		if err != nil {
			continue
		}
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(p); err == nil {
			sent++
		}
		c.Close()
	}
	if rawWake(p) == nil {
		sent++
	}
	if sent == 0 {
		return errors.New("could not send the wake-up packet")
	}
	return nil
}

// rawWake sends the packet as an Ethernet frame (ethertype 0x0842, broadcast) out of the LAN bridge: the form wired network cards listen for.
func rawWake(payload []byte) error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	frame := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ifc.HardwareAddr...)
	frame = append(frame, 0x08, 0x42)
	frame = append(frame, payload...)
	sa := &syscall.SockaddrLinklayer{Protocol: 0x4208, Ifindex: ifc.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	return syscall.Sendto(fd, frame, 0, sa)
}
