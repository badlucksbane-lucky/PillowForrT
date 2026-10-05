package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLink(t *testing.T) (*linkHist, *[]evt, *time.Time) {
	now := time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC)
	var got []evt
	h := newLinkHist(filepath.Join(t.TempDir(), "link.json"))
	h.now = func() time.Time { return now }
	h.emit = func(e evt) { got = append(got, e) }
	h.lastSave = now
	return h, &got, &now
}

func TestLinkBucketsAndView(t *testing.T) {
	h, _, now := testLink(t)
	for i := 0; i < 4; i++ {
		h.Record(true, float64(100*(i+1))) // 100..400 ms
		*now = now.Add(30 * time.Second)
	}
	h.Record(false, 0)
	*now = now.Add(time.Hour) // next hour: nothing but a gap in between? no: this is the adjacent hour
	h.Record(true, 50)
	v := h.View(3)
	if len(v.T) != 3 || v.Probes != 6 {
		t.Fatalf("%+v", v)
	}
	// slots oldest first: hour-1 (data), hour (data now), earlier hour: check ordering and values
	var dataSlots int
	for i := range v.T {
		if v.Avg[i] != nil || v.Loss[i] != nil {
			dataSlots++
		}
	}
	if dataSlots != 2 || v.Avg[2] == nil || *v.Avg[2] != 50 || v.Avg[1] == nil || *v.Avg[1] != 250 || *v.Max[1] != 400 || *v.Loss[1] < 19.9 || *v.Loss[1] > 20.1 {
		t.Errorf("avg %v max %v loss %v", v.Avg, v.Max, v.Loss)
	}
	if v.Avg[0] != nil || v.Loss[0] != nil {
		t.Error("an hour with no probes is a gap, never zero")
	}
	if v.LossPct < 16 || v.LossPct > 17 {
		t.Errorf("1 of 6 failed: %v", v.LossPct)
	}
}

func TestLinkOutageLog(t *testing.T) {
	h, _, now := testLink(t)
	h.Record(true, 80)
	*now = now.Add(30 * time.Second)
	h.Record(false, 0) // first failure
	start := now.Unix()
	*now = now.Add(30 * time.Second)
	h.Record(false, 0)
	if v := h.View(1); len(v.Outages) != 0 || v.OutageNow {
		t.Error("two failures are not an outage yet")
	}
	*now = now.Add(30 * time.Second)
	h.Record(false, 0)
	v := h.View(1)
	if !v.OutageNow || len(v.Outages) != 1 || v.Outages[0].Start != start || !v.Outages[0].Open {
		t.Fatalf("three in a row open an outage that started at the first failure: %+v", v.Outages)
	}
	*now = now.Add(5 * time.Minute)
	h.Record(true, 90)
	v = h.View(1)
	if v.OutageNow || v.Outages[0].Open || v.Outages[0].Secs != now.Unix()-start || v.Outages24 != 1 {
		t.Errorf("a success closes it with its length: %+v", v)
	}
	// a restart while an outage was open must not leave it open forever
	h.Record(false, 0)
	h.Record(false, 0)
	h.Record(false, 0)
	h.save()
	h2 := newLinkHist(h.path)
	if o := h2.outages[len(h2.outages)-1]; o.Open {
		t.Error("an outage open at a restart is closed on load")
	}
}

func TestFlakyVerdict(t *testing.T) {
	mk := func(fails ...int) []bool {
		r := make([]bool, linkWindow)
		for i := range r {
			r[i] = true
		}
		for _, f := range fails {
			r[f] = false
		}
		return r
	}
	if f, _ := flakyVerdict(mk(1, 5, 9), 0); f {
		t.Error("3 of 20 is not flaky")
	}
	if f, n := flakyVerdict(mk(1, 5, 9, 14), 0); !f || n != 4 {
		t.Error("4 of 20 is flaky")
	}
	if f, _ := flakyVerdict(mk(16, 17, 18, 19), 4); f {
		t.Error("a run of failures right now is the 'down' event's job")
	}
	if f, _ := flakyVerdict(mk(1, 5, 9, 14)[:10], 0); f {
		t.Error("needs a full window")
	}
}

func TestLinkFlakyEventOnceAnd(t *testing.T) {
	h, got, now := testLink(t)
	for i := 0; i < 40; i++ {
		*now = now.Add(30 * time.Second)
		h.Record(i%4 != 0, 100) // 25% failing, never three in a row
	}
	if len(*got) != 1 || (*got)[0].Kind != "uplink_flaky" || strings.Contains((*got)[0].Public, "%") {
		t.Fatalf("one flaky event, generic public text: %v", *got)
	}
	for i := 0; i < 80; i++ {
		*now = now.Add(30 * time.Second)
		h.Record(i%4 != 0, 100)
	}
	if len(*got) < 2 {
		t.Error("after 30 minutes it may speak again")
	}
	h2, got2, now2 := testLink(t)
	for i := 0; i < 60; i++ {
		*now2 = now2.Add(30 * time.Second)
		h2.Record(true, 100)
	}
	if len(*got2) != 0 {
		t.Error("a healthy link raises nothing")
	}
}

func TestLinkPersistsAndIsBounded(t *testing.T) {
	h, _, now := testLink(t)
	h.Record(true, 120)
	*now = now.Add(20 * time.Minute) // past the 15-minute save interval
	h.Record(true, 130)
	h2 := newLinkHist(h.path)
	if len(h2.buckets) != 1 || h2.buckets[0].N != 2 {
		t.Errorf("history must survive a restart: %+v", h2.buckets)
	}
	for i := 0; i < linkKeepHours+50; i++ {
		*now = now.Add(time.Hour)
		h.Record(true, 100)
	}
	if len(h.buckets) != linkKeepHours {
		t.Errorf("kept %d", len(h.buckets))
	}
	for i := 0; i < 80; i++ {
		*now = now.Add(time.Minute)
		h.Record(false, 0)
	}
	if len(h.outages) > 50 {
		t.Errorf("outage log is bounded: %d", len(h.outages))
	}
}

func TestLinkDaySummary(t *testing.T) {
	h, _, now := testLink(t)
	for d := 0; d < 9; d++ {
		for i := 0; i < 4; i++ {
			h.Record(i != 3, 100) // 25% loss, 100 ms
		}
		*now = now.Add(24 * time.Hour)
	}
	v := h.View(24)
	if len(v.Days) != 7 {
		t.Fatalf("the last 7 days: %d", len(v.Days))
	}
	if d := v.Days[0]; d.Probes != 4 || d.LossPct != 25 || d.AvgMs != 100 || d.Day < v.Days[1].Day {
		t.Errorf("newest first with correct maths: %+v %+v", v.Days[0], v.Days[1])
	}
}
