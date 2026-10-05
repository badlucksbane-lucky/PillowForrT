package main

import (
	"io"
	"log"
	"net"
	"time"
)

// serveDNS runs the stub on UDP and TCP at addr (dnsmasq forwards here). At most 64 queries are in flight; extra ones get SERVFAIL at once so a
// stuck upstream cannot pile up goroutines on a 160 MB device.
func serveDNS(p *DNSProxy, addr string) error {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		pc.Close()
		return err
	}
	sem := make(chan struct{}, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				log.Printf("dns udp: %v", err)
				return
			}
			q := append([]byte(nil), buf[:n]...)
			select {
			case sem <- struct{}{}:
				go func() {
					defer func() { <-sem }()
					pc.WriteTo(p.Handle(q), from)
				}()
			default:
				if dq, err := parseQuery(q); err == nil {
					pc.WriteTo(buildRcode(q, dq, 2), from)
				}
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("dns tcp: %v", err)
				return
			}
			select {
			case sem <- struct{}{}:
				go func() {
					defer func() { <-sem }()
					serveTCPConn(p, c)
				}()
			default:
				c.Close()
			}
		}
	}()
	log.Printf("dns stub listening on %s (udp+tcp)", addr)
	return nil
}

func serveTCPConn(p *DNSProxy, c net.Conn) {
	defer c.Close()
	for i := 0; i < 20; i++ { // a few queries per connection, then close
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var h [2]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		n := int(h[0])<<8 | int(h[1])
		if n < 12 || n > 4096 {
			return
		}
		q := make([]byte, n)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		r := p.Handle(q)
		if _, err := c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...)); err != nil {
			return
		}
	}
}
