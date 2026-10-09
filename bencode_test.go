package main

import "testing"

func TestBdecode(t *testing.T) {
	v, err := bdecode([]byte("d1:ai42e1:bl3:foo3:bare1:cd1:x4:\x00\x01\x02\x03ee"))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := bdict(v)
	if n, _ := bint(m, "a"); n != 42 {
		t.Fatal("int")
	}
	if l, _ := m["b"].([]any); len(l) != 2 || l[0] != "foo" || l[1] != "bar" {
		t.Fatalf("list %v", m["b"])
	}
	c, _ := bdict(m["c"])
	if s, _ := bstr(c, "x"); s != "\x00\x01\x02\x03" {
		t.Fatal("raw bytes")
	}
	for _, bad := range []string{"", "i", "ie", "i1", "5:abc", "d1:a", "l", "x", "i1ee", "d3:abci1eei2e", "-1:a", "99999999999:a", "le0"} {
		if _, err := bdecode([]byte(bad)); err == nil {
			t.Errorf("%q should not decode", bad)
		}
	}
	deep := ""
	for i := 0; i < 20; i++ {
		deep += "l"
	}
	if _, err := bdecode([]byte(deep)); err == nil {
		t.Error("deep nesting should be refused")
	}
}
