package main

// A minimal MQTT 3.1.1 client: CONNECT with an optional user name, password and last will; PUBLISH at QoS 0 (with retain); SUBSCRIBE at QoS 0; PINGREQ; and a read
// loop that hands incoming PUBLISHes to a callback. That is all Home Assistant discovery needs, and it keeps the binary free of an MQTT library. Plain TCP only: the
// broker must be on the LAN (export.go refuses anything else), so the password never crosses the carrier.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	mqttConnect     = 1
	mqttConnack     = 2
	mqttPublish     = 3
	mqttSubscribe   = 8
	mqttSuback      = 9
	mqttPingreq     = 12
	mqttPingresp    = 13
	mqttDisconnect  = 14
	mqttKeepAliveS  = 60
	mqttMaxIncoming = 64 * 1024
)

type mqttOpts struct {
	ClientID    string
	User, Pass  string
	WillTopic   string
	WillPayload string
}

type mqttClient struct {
	conn   net.Conn
	wmu    sync.Mutex
	w      *bufio.Writer
	r      *bufio.Reader
	nextID uint16
	onMsg  func(topic string, payload []byte)
	errCh  chan error
	closed sync.Once
}

func mqttString(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	return b
}

func mqttRemaining(n int) []byte {
	var out []byte
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		out = append(out, d)
		if n == 0 {
			return out
		}
	}
}

// mqttPacket frames a control packet: type and flags in the first byte, then the remaining length, then the body.
func mqttPacket(typ byte, flags byte, body []byte) []byte {
	out := []byte{typ<<4 | flags}
	out = append(out, mqttRemaining(len(body))...)
	return append(out, body...)
}

func mqttConnectPacket(o mqttOpts) []byte {
	var body []byte
	body = append(body, mqttString("MQTT")...)
	body = append(body, 4) // protocol level 3.1.1
	flags := byte(0x02)    // clean session
	if o.WillTopic != "" {
		flags |= 0x04 | 0x20 // will flag, will retain
	}
	if o.User != "" {
		flags |= 0x80
		if o.Pass != "" {
			flags |= 0x40
		}
	}
	body = append(body, flags)
	body = append(body, 0, mqttKeepAliveS)
	body = append(body, mqttString(o.ClientID)...)
	if o.WillTopic != "" {
		body = append(body, mqttString(o.WillTopic)...)
		body = append(body, mqttString(o.WillPayload)...)
	}
	if o.User != "" {
		body = append(body, mqttString(o.User)...)
		if o.Pass != "" {
			body = append(body, mqttString(o.Pass)...)
		}
	}
	return mqttPacket(mqttConnect, 0, body)
}

func mqttPublishPacket(topic string, payload []byte, retain bool) []byte {
	body := append(mqttString(topic), payload...)
	flags := byte(0)
	if retain {
		flags = 1
	}
	return mqttPacket(mqttPublish, flags, body)
}

func mqttSubscribePacket(id uint16, topic string) []byte {
	body := []byte{byte(id >> 8), byte(id)}
	body = append(body, mqttString(topic)...)
	body = append(body, 0) // QoS 0
	return mqttPacket(mqttSubscribe, 0x02, body)
}

// mqttReadPacket reads one control packet: its type, flags and body.
func mqttReadPacket(r *bufio.Reader) (typ, flags byte, body []byte, err error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; i < 4; i++ {
		d, err := r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		n += int(d&0x7f) * mult
		if d&0x80 == 0 {
			break
		}
		mult *= 128
		if i == 3 {
			return 0, 0, nil, errors.New("bad remaining length")
		}
	}
	if n > mqttMaxIncoming {
		return 0, 0, nil, errors.New("packet too large")
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	return h >> 4, h & 0x0f, body, nil
}

// mqttDial connects, sends CONNECT and waits for a clean CONNACK; then the read loop runs until the connection fails.
func mqttDial(conn net.Conn, o mqttOpts, onMsg func(topic string, payload []byte)) (*mqttClient, error) {
	c := &mqttClient{conn: conn, w: bufio.NewWriter(conn), r: bufio.NewReader(conn), onMsg: onMsg, errCh: make(chan error, 1), nextID: 1}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.w.Write(mqttConnectPacket(o)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.w.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	typ, _, body, err := mqttReadPacket(c.r)
	if err != nil {
		conn.Close()
		return nil, errors.New("no answer from the broker")
	}
	if typ != mqttConnack || len(body) < 2 {
		conn.Close()
		return nil, errors.New("the broker did not answer with CONNACK")
	}
	if body[1] != 0 {
		conn.Close()
		switch body[1] {
		case 4, 5:
			return nil, errors.New("the broker refused the user name or password")
		case 2:
			return nil, errors.New("the broker refused the client id")
		}
		return nil, errors.New("the broker refused the connection")
	}
	conn.SetDeadline(time.Time{})
	go c.readLoop()
	return c, nil
}

func (c *mqttClient) send(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *mqttClient) Publish(topic string, payload []byte, retain bool) error {
	return c.send(mqttPublishPacket(topic, payload, retain))
}

func (c *mqttClient) Subscribe(topic string) error {
	c.wmu.Lock()
	id := c.nextID
	c.nextID++
	if c.nextID == 0 {
		c.nextID = 1
	}
	c.wmu.Unlock()
	return c.send(mqttSubscribePacket(id, topic))
}

func (c *mqttClient) Ping() error { return c.send(mqttPacket(mqttPingreq, 0, nil)) }

// Err delivers the first read-loop failure (a closed socket, a bad packet).
func (c *mqttClient) Err() <-chan error { return c.errCh }

func (c *mqttClient) Close() {
	c.closed.Do(func() {
		c.send(mqttPacket(mqttDisconnect, 0, nil))
		c.conn.Close()
	})
}

func (c *mqttClient) readLoop() {
	for {
		c.conn.SetReadDeadline(time.Now().Add(2 * mqttKeepAliveS * time.Second))
		typ, flags, body, err := mqttReadPacket(c.r)
		if err != nil {
			select {
			case c.errCh <- err:
			default:
			}
			c.conn.Close()
			return
		}
		switch typ {
		case mqttPublish:
			qos := (flags >> 1) & 3
			if len(body) < 2 {
				continue
			}
			tl := int(binary.BigEndian.Uint16(body))
			if 2+tl > len(body) {
				continue
			}
			topic := string(body[2 : 2+tl])
			rest := body[2+tl:]
			if qos > 0 {
				if len(rest) < 2 {
					continue
				}
				rest = rest[2:] // we subscribed at QoS 0, but a broker may still downgrade; drop the packet id either way, no ack is sent
			}
			if c.onMsg != nil {
				c.onMsg(topic, append([]byte{}, rest...))
			}
		case mqttPingresp, mqttSuback:
		}
	}
}
