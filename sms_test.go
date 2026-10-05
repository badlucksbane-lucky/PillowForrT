package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const smsCSV = "ID,PHONE,DIRECTION,STATUS,TIME,CONTENT\n" +
	"3,+15551230001,1,0,1790000300,\"Your code is 123456, don't share\"\n" +
	"2,22000,1,1,1790000200,\"Line one\nline two with \"\"quotes\"\"\"\n" +
	"1,+15551230002,2,0,1790000100,sent text\n" +
	"4,,0,0,1790000050,a draft\n"

func TestParseSMS(t *testing.T) {
	m, err := parseSMSCSV(smsCSV)
	if err != nil || len(m) != 4 {
		t.Fatalf("%v %d", err, len(m))
	}
	if m[0].ID != 3 || !m[0].Unread || m[0].Direction != "received" || !strings.Contains(m[0].Content, "123456") {
		t.Errorf("%+v", m[0])
	}
	if m[1].Unread || m[1].Content != "Line one\nline two with \"quotes\"" {
		t.Errorf("multi-line quoted content: %+v", m[1])
	}
	if m[2].Direction != "sent" || m[2].Unread || m[3].Direction != "draft" || m[3].Unread {
		t.Errorf("only received, status-0 messages are unread: %+v %+v", m[2], m[3])
	}
	for i := 1; i < len(m); i++ {
		if m[i-1].Time < m[i].Time {
			t.Error("not newest first")
		}
	}
	if _, err := parseSMSCSV("ID,PHONE\n\"unterminated"); err == nil {
		t.Error("a broken CSV was accepted")
	}
}

func TestReadSMSCapsAndCounts(t *testing.T) {
	old := smsQuery
	defer func() { smsQuery = old }()
	var b strings.Builder
	b.WriteString("ID,PHONE,DIRECTION,STATUS,TIME,CONTENT\n")
	for i := 0; i < smsMax+1; i++ {
		b.WriteString(strings.Join([]string{strconv.Itoa(i), "1", "1", "0", strconv.Itoa(1000 + i), "x"}, ",") + "\n")
	}
	smsQuery = func(sql string) (string, error) {
		if strings.Contains(sql, "count(*)") {
			return "n,p\n300,2\n", nil
		}
		return b.String(), nil
	}
	v, err := readSMS()
	if err != nil || len(v.Messages) != smsMax || !v.Capped || v.Total != 300 || v.Partial != 2 || v.Unread != smsMax {
		t.Errorf("%v %+v", err, struct{ N, T, P, U int }{len(v.Messages), v.Total, v.Partial, v.Unread})
	}
}

func TestSMSQueryRefusesWhileJournalOpen(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "cpe.db")
	os.WriteFile(db, []byte("x"), 0o600)
	os.WriteFile(db+"-journal", []byte("x"), 0o600)
	old := *smsDBFile
	*smsDBFile = db
	defer func() { *smsDBFile = old }()
	if _, err := smsQuery("select 1;"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("journal present: %v", err)
	}
}
