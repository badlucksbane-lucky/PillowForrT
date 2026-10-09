package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// maskedFrame builds a client-to-server frame (always masked).
func maskedFrame(fin bool, op byte, p []byte) []byte {
	key := [4]byte{1, 2, 3, 4}
	b0 := op
	if fin {
		b0 |= 0x80
	}
	h := []byte{b0}
	switch {
	case len(p) < 126:
		h = append(h, 0x80|byte(len(p)))
	case len(p) < 1<<16:
		h = append(h, 0x80|126, byte(len(p)>>8), byte(len(p)))
	default:
		h = append(h, 0x80|127, 0, 0, 0, 0, byte(len(p)>>24), byte(len(p)>>16), byte(len(p)>>8), byte(len(p)))
	}
	h = append(h, key[:]...)
	for i, c := range p {
		h = append(h, c^key[i&3])
	}
	return h
}

func TestWSHeaderSizesRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 125, 126, 16 << 10, 65535, 65536, 100000} {
		p := bytes.Repeat([]byte{0xAB}, n)
		buf := make([]byte, wsMaxHeader+n)
		copy(buf[wsMaxHeader:], p)
		hl := wsHeader(buf[:wsMaxHeader], 0x2, n)
		frame := buf[wsMaxHeader-hl:]
		// parse as a client would (unmasked server frame)
		if frame[0] != 0x82 {
			t.Fatalf("n=%d: first byte %#x", n, frame[0])
		}
		var got, off int
		switch {
		case frame[1] < 126:
			got, off = int(frame[1]), 2
		case frame[1] == 126:
			got, off = int(frame[2])<<8|int(frame[3]), 4
		default:
			got, off = int(frame[6])<<24|int(frame[7])<<16|int(frame[8])<<8|int(frame[9]), 10
		}
		if got != n || !bytes.Equal(frame[off:], p) {
			t.Errorf("n=%d: header says %d, payload %d bytes", n, got, len(frame)-off)
		}
		var out bytes.Buffer
		wsWrite(&out, 0x2, p)
		if !bytes.Equal(out.Bytes(), frame) {
			t.Errorf("n=%d: wsWrite differs from the in-place frame", n)
		}
	}
}

func TestWSReadFragmentsPingAndReuse(t *testing.T) {
	cs, sc := net.Pipe()
	defer cs.Close()
	var in bytes.Buffer
	in.Write(maskedFrame(false, 0x2, []byte("hello ")))
	in.Write(maskedFrame(true, 0x9, []byte("ping"))) // a ping between fragments must not leak into the message
	in.Write(maskedFrame(true, 0x0, []byte("world")))
	big := bytes.Repeat([]byte{7}, 70000)
	in.Write(maskedFrame(true, 0x2, big))
	in.Write(maskedFrame(true, 0x2, []byte("small")))
	go func() { // the pong the ping provokes
		io.Copy(io.Discard, sc)
	}()
	br := bufio.NewReader(&in)
	var wmu sync.Mutex
	var buf []byte
	for i, want := range [][]byte{[]byte("hello world"), big, []byte("small")} {
		msg, err := wsRead(br, cs, &wmu, buf)
		if err != nil || !bytes.Equal(msg, want) {
			t.Fatalf("message %d: err %v, got %d bytes", i, err, len(msg))
		}
		buf = msg
	}
	if _, err := wsRead(br, cs, &wmu, buf); err != io.EOF {
		t.Errorf("at the end: %v, want EOF", err)
	}
}

func TestWSReadRefusesHugeAndUnmasked(t *testing.T) {
	var wmu sync.Mutex
	for name, frame := range map[string][]byte{
		"too big":  maskedFrame(true, 0x2, make([]byte, wsMaxMessage+1)),
		"unmasked": {0x82, 0x01, 'x'},
		"big ping": maskedFrame(true, 0x9, make([]byte, 126)),
	} {
		if _, err := wsRead(bufio.NewReader(bytes.NewReader(frame)), nil, &wmu, nil); err == nil || err == io.EOF {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}
