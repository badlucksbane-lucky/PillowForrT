package main

// The SOCKS5 client the box uses to reach Tor's own SOCKS port (loopback only): search, the connectivity checks and the box's own dialer go out through Tor this way, letting Tor resolve the name.
// (There is no .onion access of any kind on this box: see tor.go.)

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// torSocksAddr is Tor's SOCKS port. It listens on the loopback address only; nothing on the LAN can use it.
const torSocksAddr = "127.0.0.1:9050"

// socksRequest builds the SOCKS5 CONNECT request for a host name.
func socksRequest(host string, port int) []byte {
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	return binary.BigEndian.AppendUint16(req, uint16(port))
}

// socksConnect opens a connection to host:port through a SOCKS5 proxy, letting the proxy resolve the name.
func socksConnect(proxy, host string, port int, timeout time.Duration) (net.Conn, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("bad host name")
	}
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 5 || r[1] != 0 {
		c.Close()
		return nil, errors.New("SOCKS handshake refused")
	}
	if _, err := c.Write(socksRequest(host, port)); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 5 {
		c.Close()
		return nil, errors.New("SOCKS reply malformed")
	}
	if rep[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("Tor could not connect (SOCKS reply %d)", rep[1])
	}
	skip := 0
	switch rep[3] { // the bound address that follows: skip it
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
