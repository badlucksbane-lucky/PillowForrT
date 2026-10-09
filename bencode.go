package main

// A small bencode decoder (BEP 3) for what the torrent bridge reads off the network: tracker answers and DHT messages. It is bounded (depth and size) because both come from strangers.
// Strings come back as Go strings holding the raw bytes, integers as int64, lists as []any, dictionaries as map[string]any.

import (
	"errors"
	"strconv"
)

var errBencode = errors.New("bad bencode")

const bencodeMaxDepth = 8

func bdecode(b []byte) (any, error) {
	v, n, err := bdecodeAt(b, 0, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, errBencode
	}
	return v, nil
}

func bdecodeAt(b []byte, i, depth int) (any, int, error) {
	if depth > bencodeMaxDepth || i >= len(b) {
		return nil, 0, errBencode
	}
	switch c := b[i]; {
	case c == 'i':
		end := i + 1
		for end < len(b) && b[end] != 'e' {
			end++
		}
		if end >= len(b) || end == i+1 || end-i > 21 {
			return nil, 0, errBencode
		}
		n, err := strconv.ParseInt(string(b[i+1:end]), 10, 64)
		if err != nil {
			return nil, 0, errBencode
		}
		return n, end + 1, nil
	case c == 'l':
		var out []any
		i++
		for {
			if i >= len(b) {
				return nil, 0, errBencode
			}
			if b[i] == 'e' {
				return out, i + 1, nil
			}
			if len(out) >= 1000 {
				return nil, 0, errBencode
			}
			v, n, err := bdecodeAt(b, i, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, v)
			i = n
		}
	case c == 'd':
		out := map[string]any{}
		i++
		for {
			if i >= len(b) {
				return nil, 0, errBencode
			}
			if b[i] == 'e' {
				return out, i + 1, nil
			}
			if len(out) >= 200 {
				return nil, 0, errBencode
			}
			k, n, err := bdecodeAt(b, i, depth+1)
			ks, ok := k.(string)
			if err != nil || !ok {
				return nil, 0, errBencode
			}
			v, n2, err := bdecodeAt(b, n, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out[ks] = v
			i = n2
		}
	case c >= '0' && c <= '9':
		colon := i
		for colon < len(b) && b[colon] != ':' {
			colon++
		}
		if colon >= len(b) || colon-i > 9 {
			return nil, 0, errBencode
		}
		n, err := strconv.Atoi(string(b[i:colon]))
		if err != nil || n < 0 || colon+1+n > len(b) {
			return nil, 0, errBencode
		}
		return string(b[colon+1 : colon+1+n]), colon + 1 + n, nil
	}
	return nil, 0, errBencode
}

// bstr, bint and bdict read a typed field out of a decoded dictionary.
func bstr(m map[string]any, k string) (string, bool) { s, ok := m[k].(string); return s, ok }
func bint(m map[string]any, k string) (int64, bool)  { n, ok := m[k].(int64); return n, ok }
func bdict(v any) (map[string]any, bool)             { m, ok := v.(map[string]any); return m, ok }
