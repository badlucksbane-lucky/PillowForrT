package main

// Read-only SMS inbox. The stock firmware keeps messages in the SQLite file /usrdata/data/usr/cpe.db (table DBTABLESMS: ID, PHONE, DIRECTION, STATUS, TIME, CONTENT;
// DIRECTION 1 = received, 2 = sent, 0 = draft; STATUS 0 = unread, 1 = read; TIME is unix seconds), written by the `sms` daemon from the SIM and the modem. Long messages
// arrive in parts and wait in DBTABLECASCADE until complete. We never open the live file: it is copied to the RAM disk (retried if the daemon has a journal open), queried
// there with the box's own sqlite3 (3.8: no -readonly, no -json, so CSV), and the copy is deleted. Nothing here writes, sends or deletes (sending needs the modem, may
// cost money, and is outward-facing), and reading a message here does not mark it read in the stock admin. Message text never goes to logs, /status.json or the vantage node.

import (
	"encoding/csv"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type smsMessage struct {
	ID        int    `json:"id"`
	Phone     string `json:"phone"`
	Direction string `json:"direction"` // received | sent | draft
	Unread    bool   `json:"unread"`
	Time      int64  `json:"time"`
	Content   string `json:"content"`
}

type smsView struct {
	Messages []smsMessage `json:"messages"`
	Total    int          `json:"total"`
	Unread   int          `json:"unread"`
	Partial  int          `json:"partial"` // long messages still waiting for their other parts
	Capped   bool         `json:"capped,omitempty"`
}

const smsMax = 200

func parseSMSCSV(out string) ([]smsMessage, error) {
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		return nil, err
	}
	var msgs []smsMessage
	for i, r := range rows {
		if i == 0 || len(r) < 6 {
			continue // header
		}
		id, _ := strconv.Atoi(r[0])
		dir, _ := strconv.Atoi(r[2])
		st, _ := strconv.Atoi(r[3])
		t, _ := strconv.ParseInt(r[4], 10, 64)
		m := smsMessage{ID: id, Phone: r[1], Unread: dir == 1 && st == 0, Time: t, Content: r[5]}
		switch dir {
		case 1:
			m.Direction = "received"
		case 2:
			m.Direction = "sent"
		default:
			m.Direction = "draft"
		}
		msgs = append(msgs, m)
	}
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].Time > msgs[j].Time })
	return msgs, nil
}

// smsQuery runs one SELECT against a private copy of the database and returns CSV with a header row.
var smsQuery = func(sql string) (string, error) {
	src := *smsDBFile
	var data []byte
	for try := 0; try < 4; try++ {
		if _, err := os.Stat(src + "-journal"); err == nil { // the daemon is mid-write: wait and look again
			time.Sleep(250 * time.Millisecond)
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(src + "-journal"); err != nil {
			data = b
			break
		}
	}
	if data == nil {
		return "", errors.New("the message store is busy: try again in a moment")
	}
	f, err := os.CreateTemp("/var/volatile", "sms-view-*.db")
	if err != nil {
		f, err = os.CreateTemp("", "sms-view-*.db")
		if err != nil {
			return "", err
		}
	}
	defer os.Remove(f.Name())
	f.Chmod(0o600)
	f.Write(data)
	f.Close()
	out, err := run("sqlite3", "-csv", "-header", f.Name(), sql)
	if err != nil {
		return "", errors.New("could not read the message store")
	}
	return out, nil
}

func readSMS() (smsView, error) {
	v := smsView{Messages: []smsMessage{}}
	out, err := smsQuery("select ID,PHONE,DIRECTION,STATUS,TIME,CONTENT from DBTABLESMS order by TIME desc, ID desc limit " + strconv.Itoa(smsMax+1) + ";")
	if err != nil {
		return v, err
	}
	msgs, err := parseSMSCSV(out)
	if err != nil {
		return v, errors.New("the message store gave an unreadable answer")
	}
	if len(msgs) > smsMax {
		msgs, v.Capped = msgs[:smsMax], true
	}
	v.Messages = msgs
	for _, m := range msgs {
		if m.Unread {
			v.Unread++
		}
	}
	if c, err := smsQuery("select (select count(*) from DBTABLESMS) as n, (select count(*) from DBTABLECASCADE) as p;"); err == nil {
		if rows, e := csv.NewReader(strings.NewReader(c)).ReadAll(); e == nil && len(rows) == 2 && len(rows[1]) == 2 {
			v.Total, _ = strconv.Atoi(rows[1][0])
			v.Partial, _ = strconv.Atoi(rows[1][1])
		}
	}
	if v.Total < len(v.Messages) {
		v.Total = len(v.Messages)
	}
	return v, nil
}
