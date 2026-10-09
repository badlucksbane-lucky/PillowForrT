package main

// The Nyaa relay for the browse page (browse.html). Nyaa's RSS carries no CORS header, so a browser cannot read it; everything else the page needs it fetches itself. This fetches one Nyaa
// RSS search over the chosen proxy and DNS path (search.go) and hands back the few fields the page shows. The magnet link is built in the page from the hash.

import (
	"context"
	"encoding/xml"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type nyaaItem struct {
	Title string `json:"title"`
	Hash  string `json:"hash"`
	Seeds int    `json:"seeds"`
	Size  string `json:"size"`
	URL   string `json:"url"`
}

const nyaaMax = 40

var nyaaHashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func parseNyaa(b []byte) ([]nyaaItem, error) {
	var d struct {
		Items []struct {
			Title    string `xml:"title"`
			GUID     string `xml:"guid"`
			Seeders  string `xml:"https://nyaa.si/xmlns/nyaa seeders"`
			InfoHash string `xml:"https://nyaa.si/xmlns/nyaa infoHash"`
			Size     string `xml:"https://nyaa.si/xmlns/nyaa size"`
		} `xml:"channel>item"`
	}
	if xml.Unmarshal(b, &d) != nil {
		return nil, errors.New("unexpected answer")
	}
	out := []nyaaItem{}
	for _, it := range d.Items {
		h := strings.ToLower(strings.TrimSpace(it.InfoHash))
		if !nyaaHashRe.MatchString(h) || strings.TrimSpace(it.Title) == "" || len(out) >= nyaaMax {
			continue
		}
		seeds, _ := strconv.Atoi(strings.TrimSpace(it.Seeders))
		page := ""
		if strings.HasPrefix(it.GUID, "https://nyaa.si/view/") {
			page = it.GUID
		}
		out = append(out, nyaaItem{Title: strings.TrimSpace(it.Title), Hash: h, Seeds: seeds, Size: strings.TrimSpace(it.Size), URL: page})
	}
	return out, nil
}

// Nyaa runs one search for the browse page. Off, or a path that is down, is an error and nothing is sent.
func (m *searchMgr) Nyaa(ctx context.Context, q string) ([]nyaaItem, error) {
	cfg := m.Config()
	if !cfg.Enabled {
		return nil, errors.New("Search is off")
	}
	if q == "" {
		return []nyaaItem{}, nil
	}
	st := m.state()
	if err := searchPathReady(cfg.Proxy, st); err != nil {
		return nil, errors.New("Proxy " + searchModeLabel(cfg.Proxy) + ": " + err.Error())
	}
	if err := searchPathReady(cfg.DNS, st); err != nil {
		return nil, errors.New("DNS " + searchModeLabel(cfg.DNS) + ": " + err.Error())
	}
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		return nil, errors.New("busy")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	cl := m.client(cfg)
	defer cl.CloseIdleConnections()
	b, err := searchGet(ctx, cl, "https://nyaa.si/?page=rss&q="+url.QueryEscape(q), browserUA, "application/rss+xml")
	if err != nil {
		return nil, errors.New(searchErrText(err, q))
	}
	return parseNyaa(b)
}
