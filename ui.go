package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed ui.html
var uiHTML []byte

var (
	dnsProxy    *DNSProxy
	dnsUpdater  *listUpdater
	uiTokenFile string
)

// uiTokenOK: does the request carry the script API-key token? With no token file configured the token is OFF and nothing matches (it must fail closed:
// "no file" once meant "accept any header", which opened the whole API to anyone on the LAN).
func uiTokenOK(r *http.Request) bool {
	if uiTokenFile == "" {
		return false
	}
	want, err := os.ReadFile(uiTokenFile)
	if err != nil || len(strings.TrimSpace(string(want))) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(want))), []byte(r.Header.Get("X-UI-Token"))) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// dnsStatus is the DNS half of the web page and of /status.json.
func dnsStatus() map[string]any {
	if dnsProxy == nil {
		return map[string]any{"enabled": false}
	}
	f := dnsProxy.Filter
	sn := dnsProxy.Stats.Snapshot(10, 40)
	names := deviceNames(*leasesFile, *dhcpHostsFile)
	modes := f.DeviceModes()
	seen := map[string]bool{}
	for i := range sn.Clients {
		sn.Clients[i].Name = names[sn.Clients[i].IP]
		sn.Clients[i].Mode = modes[sn.Clients[i].IP]
		seen[sn.Clients[i].IP] = true
	}
	for ip, m := range modes { // an override for a device that has not asked lately still shows, so it can be changed back
		if !seen[ip] {
			sn.Clients = append(sn.Clients, clientView{IP: ip, Name: names[ip], Mode: m})
		}
	}
	m := map[string]any{
		"enabled": true, "mode": f.Mode(), "lists": f.Lists(), "allow": f.AllowList(), "custom": f.CustomRules(), "budget": map[string]int{"entries": f.TotalEntries(), "max": maxTotalEntries},
		"upstream": dnsProxy.Up.State(), "stats": sn, "cache_entries": dnsProxy.Cache.Len(),
	}
	if p := f.PausedUntil(); !p.IsZero() {
		m["paused_until"] = p
	}
	return m
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(uiHTML)
}

func handleVPNAPI(w http.ResponseWriter, r *http.Request, path string) {
	if vpn == nil {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	if r.Method == http.MethodGet && path == "vpn" {
		vpn.EnsureRelays()
		writeJSON(w, 200, vpnStatusJSON())
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "not found", 404)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var b struct {
		Account, Country, City, Exit, IP, Tier string
		On                                     bool
	}
	json.NewDecoder(r.Body).Decode(&b)
	var err error
	switch strings.TrimPrefix(path, "vpn/") {
	case "register":
		err = vpn.Register(b.Account)
	case "remove":
		err = vpn.Remove(b.Account)
	case "enable":
		err = vpn.SetEnabled(b.On)
	case "relay":
		err = vpn.SetRelay(b.Country, b.City)
	case "default":
		err = vpn.SetDefaultExit(b.Exit)
	case "device":
		if b.Exit == "mullvad" || b.Exit == "direct" {
			err = liveModeDeps().set(b.IP, "", b.Exit) // moving a Tor device to an exit takes it off Tor too, after the exit is in place
		} else {
			err = vpn.SetDeviceExit(b.IP, b.Exit)
		}
	case "killswitch":
		vpn.SetKillSwitch(b.On)
	case "tier":
		err = vpn.SetKillTier(b.Tier, func(t string) error {
			wanted, _, _ := vpn.OwnState()
			torOn, torVPN := torMgrG.Switches()
			return killTierPrereq(t, wanted, torOn, torVPN)
		})
	case "dnsvpn":
		vpn.SetDNSViaVPN(b.On)
	case "panic":
		vpn.Panic()
	default:
		http.Error(w, "not found", 404)
		return
	}
	b.Account = "" // never kept
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, vpnStatusJSON())
}

// vpnStatusJSON is the VPN status plus which rung is serving the router's own traffic (owndial.go).
func vpnStatusJSON() any {
	return struct {
		vpnStatus
		Own ownView `json:"own"`
	}{vpn.Status(), ownR.View()}
}

// handleAccount: who is logged in (with the CSRF token the page must send), and changing the password.
func handleAccount(w http.ResponseWriter, r *http.Request, path string) {
	s, _ := r.Context().Value(sessionKey).(*session)
	switch {
	case path == "session" && r.Method == http.MethodGet:
		if s == nil {
			writeJSON(w, 200, map[string]string{"user": "token", "csrf": ""})
			return
		}
		writeJSON(w, 200, map[string]string{"user": s.User, "csrf": s.CSRF})
	case path == "account/password" && r.Method == http.MethodPost:
		if webAuth == nil {
			http.Error(w, "not found", 404)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var b struct{ Old, New string }
		json.NewDecoder(r.Body).Decode(&b)
		user := webAuth.User()
		if webAuth.Throttled(clientAddr(r)) {
			writeJSON(w, 429, map[string]string{"error": "too many failed attempts: wait ten minutes"})
			return
		}
		if !webAuth.Check(user, b.Old) {
			webAuth.RecordFail(clientAddr(r))
			writeJSON(w, 400, map[string]string{"error": "the current password is wrong"})
			return
		}
		if err := webAuth.SetLogin(user, b.New); err != nil { // also ends every session, this one included
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "password changed: sign in again"})
	default:
		http.Error(w, "not found", 404)
	}
}

var (
	wifi     *wifiManager
	dhcpMgr  *dhcpManager
	poolMgr  *poolManager
	macMgr   *macFilter
	fwMgr    *fwManager
	snaps    *snapStore
	sshMgr   *sshManager
	certMgr  *certManager
	stockMgr *stockAdmin
	lanV6Mgr *lanV6
	egressM  *egressMgr
	devMgr   *devNotes
)

func lanNames() (names, ipOfMAC map[string]string) {
	arp, _ := os.ReadFile("/proc/net/arp")
	lease, _ := os.ReadFile(*leasesFile)
	names = deviceNames(*leasesFile, *dhcpHostsFile)
	ipOfMAC = map[string]string{}
	for ip, mac := range macMapFromARP(string(arp), string(lease)) {
		ipOfMAC[mac] = ip
	}
	return
}

func handleSettings(w http.ResponseWriter, r *http.Request, path string) {
	if wifi == nil || dhcpMgr == nil || poolMgr == nil || macMgr == nil || fwMgr == nil {
		http.Error(w, "not found", 404)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	switch {
	case path == "wifi" && r.Method == http.MethodGet:
		names, ipOf := lanNames()
		v, err := wifi.View(names, ipOf)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, v)
	case path == "wifi/apply" && r.Method == http.MethodPost:
		var c wifiChange
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		msg, err := wifi.Apply(c)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 202, map[string]string{"status": msg})
	case path == "wifi/restore" && r.Method == http.MethodPost:
		var b struct{ Backup string }
		json.NewDecoder(r.Body).Decode(&b)
		msg, err := wifi.Restore(b.Backup)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 202, map[string]string{"status": msg})
	case path == "wifi/kick" && r.Method == http.MethodPost:
		var b struct{ MAC string }
		json.NewDecoder(r.Body).Decode(&b)
		if err := wifi.Kick(b.MAC); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "disconnected: the device will rejoin"})
	case path == "dhcp" && r.Method == http.MethodGet:
		arp, _ := os.ReadFile("/proc/net/arp")
		lease, _ := os.ReadFile(*leasesFile)
		cmd := ""
		if pid, err := os.ReadFile("/data/dnsmasq.pid"); err == nil {
			if b, err := os.ReadFile("/proc/" + strings.TrimSpace(string(pid)) + "/cmdline"); err == nil {
				cmd = strings.ReplaceAll(string(b), "\x00", " ")
			}
		}
		writeJSON(w, 200, dhcpMgr.View(string(arp), string(lease), parseStations(wifi.env.stations()), cmd))
	case path == "system/stockadmin" && r.Method == http.MethodGet:
		writeJSON(w, 200, stockMgr.View())
	case path == "system/stockadmin" && r.Method == http.MethodPost:
		var b struct{ Off bool }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := stockMgr.Set(b.Off); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		msg := "the stock admin is switched back on"
		if b.Off {
			msg = "the stock admin is switched off for the network"
		}
		writeJSON(w, 200, map[string]any{"status": msg, "state": stockMgr.View()})
	case path == "system/lanv6" && r.Method == http.MethodGet:
		writeJSON(w, 200, lanV6Mgr.View())
	case path == "system/lanv6" && r.Method == http.MethodPost:
		var b struct{ Off bool }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := lanV6Mgr.Set(b.Off); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		msg := "LAN IPv6 is back on: devices get the prefix again within a few minutes"
		if b.Off {
			msg = "LAN IPv6 is off: the withdraw went out, devices drop their carrier address (at once if deprecated, within 2 hours at the latest)"
		}
		writeJSON(w, 200, map[string]any{"status": msg, "state": lanV6Mgr.View()})
	case path == "egress" && r.Method == http.MethodGet:
		writeJSON(w, 200, egressM.ViewFor(r.URL.Query().Get("mac")))
	case (path == "egress/set" || path == "egress/allow" || path == "egress/remove" || path == "egress/service" || path == "egress/httpupgrade") && r.Method == http.MethodPost:
		var b struct {
			Mode, Proto, Ports, Note, MAC, ID string
			Confirm, On                       bool
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		var err error
		switch path {
		case "egress/set":
			if b.Mode == "enforce" && !b.Confirm {
				writeJSON(w, 400, map[string]string{"error": "enforce needs confirm"})
				return
			}
			err = egressM.SetMode(b.Mode)
		case "egress/service":
			err = egressM.SetService(b.ID, b.On, b.MAC)
		case "egress/httpupgrade":
			err = egressM.SetHTTPUpgrade(b.On, b.MAC)
		case "egress/allow":
			err = egressM.Allow(egressRule{Proto: b.Proto, Ports: b.Ports, Note: b.Note}, b.MAC)
		default:
			err = egressM.Remove(egressRule{Proto: b.Proto, Ports: b.Ports}, b.MAC)
		}
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"status": "saved", "state": egressM.View()})
	case path == "diag" && r.Method == http.MethodGet:
		diagMu.Lock()
		last := diagLast
		diagMu.Unlock()
		if last == nil {
			writeJSON(w, 200, map[string]any{"ran": false})
			return
		}
		writeJSON(w, 200, last)
	case path == "diag/run" && r.Method == http.MethodPost:
		writeJSON(w, 200, runDiag())
	case path == "diag/report" && r.Method == http.MethodGet:
		diagMu.Lock()
		last := diagLast
		diagMu.Unlock()
		if last == nil {
			http.Error(w, "run the diagnostics first", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="pillowforrt-diagnostics.txt"`)
		w.Write([]byte(diagReport(*last)))
	case path == "cert" && r.Method == http.MethodGet:
		if certMgr == nil {
			writeJSON(w, 404, map[string]string{"error": "the web page has no certificate manager"})
			return
		}
		writeJSON(w, 200, certMgr.View())
	case path == "cert/renew" && r.Method == http.MethodPost:
		if certMgr == nil {
			writeJSON(w, 404, map[string]string{"error": "the web page has no certificate manager"})
			return
		}
		fp, err := certMgr.Renew()
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "renewed", "fingerprint": fp})
	case path == "cert/download" && r.Method == http.MethodGet:
		if certMgr == nil {
			http.Error(w, "not found", 404)
			return
		}
		pem, err := certMgr.PEM()
		if err != nil {
			http.Error(w, "no certificate", 404)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="pillowforrt-web-certificate.pem"`)
		w.Write(pem)
	case path == "cert/pillowforrt.crt" && r.Method == http.MethodGet:
		// The same public certificate, sent as a CA certificate (DER): Android's Chrome and iPhone's Safari offer to install that type when it is opened, where the .pem download above
		// only saves a file. Installing it is what lets a browser register the player's service worker, which refuses an origin with a certificate warning.
		if certMgr == nil {
			http.Error(w, "not found", 404)
			return
		}
		pemb, err := certMgr.PEM()
		der, derr := certInstallDER(pemb)
		if err != nil || derr != nil {
			http.Error(w, "no certificate", 404)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(der)
	case path == "ssh" && r.Method == http.MethodGet:
		writeJSON(w, 200, sshMgr.View())
	case (path == "ssh/add" || path == "ssh/delete") && r.Method == http.MethodPost:
		var b struct{ Key, Fingerprint string }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if path == "ssh/add" {
			fp, err := sshMgr.Add(b.Key)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "added " + fp})
			return
		}
		if err := sshMgr.Delete(b.Fingerprint); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "removed"})
	case path == "sms" && r.Method == http.MethodGet:
		v, err := readSMS()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, v)
	case path == "speed" && r.Method == http.MethodGet:
		if speedMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, speedMgr.View())
	case path == "speed/set" && r.Method == http.MethodPost:
		var b struct {
			Enabled   bool
			IntervalH int `json:"interval_h"`
		}
		if speedMgr == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := speedMgr.Set(b.Enabled, b.IntervalH); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, speedMgr.View())
	case path == "speed/run" && r.Method == http.MethodPost:
		if speedMgr == nil {
			writeJSON(w, 400, map[string]string{"error": "speed tests are not available"})
			return
		}
		busy, err := speedMgr.begin(true)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		go speedMgr.finish(busy) // takes several seconds: the page polls the view
		writeJSON(w, 200, map[string]string{"status": "started"})
	case path == "rogue-dhcp/allow" && r.Method == http.MethodPost:
		var b struct {
			MAC   string
			Allow bool
		}
		if rogueMgr == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := rogueMgr.Allow(b.MAC, b.Allow); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, rogueMgr.View())
	case path == "tor" && r.Method == http.MethodGet:
		if torMgrG == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, torMgrG.View())
	case path == "tor/set" && r.Method == http.MethodPost:
		var b struct{ Enabled bool } // the .onion settings are not here: they are changed only over SSH (onion.go, -onion)
		if torMgrG == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := torMgrG.SetEnabled(b.Enabled); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, torMgrG.View())
	case path == "tor/device" && r.Method == http.MethodPost:
		var b struct {
			MAC string
			On  bool
		}
		if torMgrG == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		var err error
		if b.On {
			err = liveModeDeps().set("", b.MAC, "tor") // a Tor device has no exit override beside it
		} else {
			err = torMgrG.SetDevice(b.MAC, false)
		}
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, torMgrG.View())
	case path == "tor/overvpn" && r.Method == http.MethodPost:
		var b struct{ On bool }
		if torMgrG == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := torMgrG.SetOverVPN(b.On); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, torMgrG.View())
	case path == "device/mode" && r.Method == http.MethodPost:
		var b struct{ IP, MAC, Mode string }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := liveModeDeps().set(b.IP, b.MAC, b.Mode); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	case path == "tor/test" && r.Method == http.MethodPost:
		if torMgrG == nil || !torMgrG.ready() {
			writeJSON(w, 400, map[string]string{"error": "Tor is not ready yet"})
			return
		}
		out, err := torSelfTest()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	case path == "arp" && r.Method == http.MethodGet:
		if arpMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, arpMgr.View())
	case path == "rogue-dhcp" && r.Method == http.MethodGet:
		if rogueMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, rogueMgr.View())
	case path == "canary" && r.Method == http.MethodGet:
		if canaryMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, canaryMgr.View())
	case (path == "canary/set" || path == "canary/ignore") && r.Method == http.MethodPost:
		if canaryMgr == nil {
			writeJSON(w, 400, map[string]string{"error": "the canary is not configured (-canary is empty)"})
			return
		}
		var b struct {
			Enabled bool
			MAC     string
			Ignore  bool
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if path == "canary/set" {
			canaryMgr.SetEnabled(b.Enabled)
		} else if err := canaryMgr.IgnoreMAC(b.MAC, b.Ignore); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "dnscanary" && r.Method == http.MethodGet:
		if dnsCanaryMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, dnsCanaryMgr.View())
	case path == "dnscanary/set" && r.Method == http.MethodPost:
		if dnsCanaryMgr == nil {
			writeJSON(w, 400, map[string]string{"error": "the DNS canary is not available (the DNS filter is off)"})
			return
		}
		var b struct{ Enabled bool }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		dnsCanaryMgr.SetEnabled(b.Enabled)
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "macchurn" && r.Method == http.MethodGet:
		if macChurnMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, macChurnMgr.View())
	case path == "torbypass" && r.Method == http.MethodGet:
		if torBypassMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, torBypassMgr.View())
	case path == "beacon" && r.Method == http.MethodGet:
		if beaconMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, beaconMgr.View())
	case path == "beacon/ignore" && r.Method == http.MethodPost:
		if beaconMgr == nil {
			writeJSON(w, 400, map[string]string{"error": "beacon detection is not available"})
			return
		}
		var b struct {
			Src, Dst string
			Ignore   bool
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		beaconMgr.Ignore(b.Src, b.Dst, b.Ignore)
		writeJSON(w, 200, beaconMgr.View())
	case path == "dganxdomain" && r.Method == http.MethodGet:
		if dgaMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, dgaMgr.View())
	case path == "tlssni" && r.Method == http.MethodGet:
		if tlsSNIMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, tlsSNIMgr.View())
	case path == "lanannounce" && r.Method == http.MethodGet:
		if lanAnnounceMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, lanAnnounceMgr.View())
	case path == "lanpoison" && r.Method == http.MethodGet:
		if lanPoisonMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, lanPoisonMgr.View())
	case path == "wifidisco" && r.Method == http.MethodGet:
		if wifiDiscoMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, wifiDiscoMgr.View())
	case path == "egressblock" && r.Method == http.MethodGet:
		if egressBlockMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, egressBlockMgr.View())
	case path == "dnsxcheck" && r.Method == http.MethodGet:
		if dnsXMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, dnsXMgr.View())
	case path == "tlscert" && r.Method == http.MethodGet:
		if tlsCertMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, tlsCertMgr.View())
	case path == "dnsmitm" && r.Method == http.MethodGet:
		if dnsMITMMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, dnsMITMMgr.View())
	case path == "dhcpfp" && r.Method == http.MethodGet:
		if dhcpFPMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, dhcpFPMgr.View())
	case path == "ttl" && r.Method == http.MethodGet:
		if ttlMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, ttlMgr.View())
	case path == "ttl/ignore" && r.Method == http.MethodPost:
		if ttlMgr == nil {
			writeJSON(w, 400, map[string]string{"error": "the hidden-router watch is off (-ttl-watch=false)"})
			return
		}
		var b struct {
			MAC    string
			Ignore bool
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := ttlMgr.IgnoreMAC(b.MAC, b.Ignore); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "admintrip" && r.Method == http.MethodGet:
		if adminTripMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, adminTripMgr.View())
	case path == "steer" && r.Method == http.MethodGet:
		if steerMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, steerMgr.View())
	case path == "steer/allow" && r.Method == http.MethodPost:
		var b struct {
			MAC   string
			Allow bool
		}
		if steerMgr == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := steerMgr.Allow(b.MAC, b.Allow); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, steerMgr.View())
	case path == "rebind" && r.Method == http.MethodGet:
		if rebindMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		writeJSON(w, 200, rebindMgr.View())
	case (path == "rebind/set" || path == "rebind/allow") && r.Method == http.MethodPost:
		if rebindMgr == nil {
			writeJSON(w, 400, map[string]string{"error": "rebinding refusal is not available (the DNS filter is off)"})
			return
		}
		var b struct {
			Enabled bool
			Pattern string
			Remove  bool
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if path == "rebind/set" {
			rebindMgr.SetEnabled(b.Enabled)
		} else if err := rebindMgr.Allow(b.Pattern, !b.Remove); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "actions" && r.Method == http.MethodGet:
		writeJSON(w, 200, actions.View())
	case (path == "actions/set" || path == "actions/delete" || path == "actions/run") && r.Method == http.MethodPost:
		var b struct {
			schedAction
			Confirm string
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		switch path {
		case "actions/set":
			id, err := actions.Set(b.schedAction, b.Confirm)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"status": "saved", "id": id})
		case "actions/delete":
			if err := actions.Delete(b.ID); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "deleted"})
		default:
			for _, a := range actions.load() {
				if a.ID == b.ID && a.Action == "reboot" && b.Confirm != "reboot" {
					writeJSON(w, 400, map[string]string{"error": `running a reboot needs the word "reboot" typed to confirm`})
					return
				}
			}
			res, err := actions.run(b.ID, true)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": res})
		}
	case path == "events" && r.Method == http.MethodGet:
		writeJSON(w, 200, events.View())
	case path == "events/seen" && r.Method == http.MethodPost:
		var b struct {
			Kinds []string `json:"kinds"` // optional: only these kinds (tor_down, rogue_dhcp, ...); none = every event
		}
		json.NewDecoder(r.Body).Decode(&b)
		n := events.MarkSeenKinds(b.Kinds)
		writeJSON(w, 200, map[string]any{"status": "marked as seen", "changed": n})
	case path == "events/clear" && r.Method == http.MethodPost:
		events.Clear()
		writeJSON(w, 200, map[string]string{"status": "cleared"})
	case path == "notify/set" && r.Method == http.MethodPost:
		var b notifyCfg
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := events.SetNotify(b); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "notify/clear" && r.Method == http.MethodPost:
		if err := events.ClearNotifyURL(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "the address was removed and notifications are off"})
	case path == "notify/test" && r.Method == http.MethodPost:
		if err := events.Test(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "a test notification was sent"})
	case path == "linkhist" && r.Method == http.MethodGet:
		if linkMgr == nil {
			writeJSON(w, 200, map[string]any{"available": false})
			return
		}
		h, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		writeJSON(w, 200, linkMgr.View(h))
	case path == "graphs" && r.Method == http.MethodGet:
		writeJSON(w, 200, graphs.View(r.URL.Query().Get("range") == "24h"))
	case path == "devices/note" && r.Method == http.MethodPost:
		var b struct{ MAC, Label, Note string }
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := devMgr.Set(b.MAC, b.Label, b.Note); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "devices/watch" && r.Method == http.MethodPost:
		var b struct {
			MAC   string
			Watch bool
		}
		json.NewDecoder(r.Body).Decode(&b)
		if presence == nil {
			writeJSON(w, 400, map[string]string{"error": "presence is not running"})
			return
		}
		if err := presence.SetWatch(b.MAC, b.Watch); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved"})
	case path == "devices/wake" && r.Method == http.MethodPost:
		var b struct{ MAC string }
		json.NewDecoder(r.Body).Decode(&b)
		if err := sendWake(strings.ToLower(strings.TrimSpace(b.MAC))); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "wake-up packet sent: wired devices and ones set up for wake-on-wireless should wake within a few seconds; most Wi-Fi devices ignore it"})
	case path == "devices" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"devices": gatherDevices()})
	case path == "system" && r.Method == http.MethodGet:
		writeJSON(w, 200, readSystem())
	case path == "system/reboot" && r.Method == http.MethodPost:
		var b struct{ Confirm string }
		json.NewDecoder(r.Body).Decode(&b)
		if err := doReboot(b.Confirm); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 202, map[string]string{"status": "rebooting in 3 seconds: every device drops for 1 to 2 minutes"})
	case path == "cell" && r.Method == http.MethodGet:
		writeJSON(w, 200, readCell())
	case path == "wifi/macfilter" && r.Method == http.MethodGet:
		names, ipOf := lanNames()
		byMAC := map[string]string{}
		for mac, ip := range ipOf {
			byMAC[mac] = names[ip]
		}
		for _, r := range dhcpMgr.List() {
			byMAC[r.MAC] = r.Name
		}
		writeJSON(w, 200, map[string]any{"blocked": macMgr.View(byMAC, wifi.env.stations())})
	case (path == "wifi/macfilter/add" || path == "wifi/macfilter/remove") && r.Method == http.MethodPost:
		var b struct{ MAC string }
		json.NewDecoder(r.Body).Decode(&b)
		var err error
		if path == "wifi/macfilter/add" {
			err = macMgr.Add(b.MAC, selfMAC(r))
		} else {
			err = macMgr.Remove(b.MAC)
		}
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "done"})
	case path == "fw" && r.Method == http.MethodGet:
		names, ipOf := lanNames()
		byMAC := map[string]string{}
		for mac, ip := range ipOf {
			byMAC[mac] = names[ip]
		}
		for _, r := range dhcpMgr.List() {
			byMAC[r.MAC] = r.Name
		}
		writeJSON(w, 200, fwMgr.View(byMAC))
	case strings.HasPrefix(path, "fw/") && r.Method == http.MethodPost:
		var b struct {
			fwSched
			CIDR    string
			Minutes int
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		var err error
		switch path {
		case "fw/dest/add":
			err = fwMgr.AddDest(b.CIDR, b.Note)
		case "fw/dest/delete":
			err = fwMgr.DeleteDest(b.CIDR)
		case "fw/sched/set":
			err = fwMgr.SetSched(b.fwSched)
		case "fw/sched/delete":
			err = fwMgr.DeleteSched(b.ID)
		case "fw/pause":
			err = fwMgr.Pause(b.MAC, b.Minutes)
		case "fw/resume":
			err = fwMgr.Resume(b.MAC)
		default:
			http.Error(w, "not found", 404)
			return
		}
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "done"})
	case path == "dhcp/pool" && r.Method == http.MethodGet:
		v, err := poolMgr.View()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, v)
	case path == "dhcp/pool/set" && r.Method == http.MethodPost:
		var b dhcpPool
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		msg, err := poolMgr.Set(b)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": msg})
	case path == "dhcp/set" && r.Method == http.MethodPost:
		var b reservation
		json.NewDecoder(r.Body).Decode(&b)
		if err := dhcpMgr.Set(b); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "saved: the device gets this address when it next renews or reconnects"})
	case path == "dhcp/move" && r.Method == http.MethodPost:
		var b struct{ MAC string }
		json.NewDecoder(r.Body).Decode(&b)
		old, err := dhcpMgr.MoveNow(b.MAC)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		wifi.Kick(b.MAC) // it rejoins and asks again; best effort (a wired or asleep device just takes it later)
		writeJSON(w, 200, map[string]string{"status": "released " + old + "; the device was disconnected and will rejoin at its reserved address"})
	case path == "dhcp/forget" && r.Method == http.MethodPost:
		var b struct{ MAC string }
		json.NewDecoder(r.Body).Decode(&b)
		ip, err := dhcpMgr.Forget(b.MAC)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "released the lease on " + ip})
	case path == "dhcp/delete" && r.Method == http.MethodPost:
		var b struct{ MAC string }
		json.NewDecoder(r.Body).Decode(&b)
		if err := dhcpMgr.Delete(b.MAC); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "not found", 404)
	}
}

// selfMAC finds the MAC of the device making this request (from its address), or "" when it cannot be told.
func selfMAC(r *http.Request) string {
	_, ipOf := lanNames()
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	for mac, ip := range ipOf {
		if ip == host {
			return mac
		}
	}
	return ""
}

func handleBackup(w http.ResponseWriter, r *http.Request, path string) {
	if snaps == nil {
		http.Error(w, "not found", 404)
		return
	}
	switch {
	case path == "backup" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"snapshots": snaps.List(), "sections": snapSections})
	case path == "backup/download" && r.Method == http.MethodGet:
		raw, err := snaps.Raw(r.URL.Query().Get("name"))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="pillowforrt-`+r.URL.Query().Get("name")+`.json"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(raw)
	case path == "backup/upload" && r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "the file is too big or unreadable"})
			return
		}
		name, err := snaps.Import(raw)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "imported as " + name, "name": name})
	case strings.HasPrefix(path, "backup/") && r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var b struct {
			Name, Label string
			Sections    []string
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		switch path {
		case "backup/create":
			name, err := snaps.Create(b.Label)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "saved as " + name, "name": name})
		case "backup/delete":
			if err := snaps.Delete(b.Name); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "deleted"})
		case "backup/restore":
			res, err := snaps.Restore(b.Name, b.Sections, selfMAC(r))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"results": res})
		default:
			http.Error(w, "not found", 404)
		}
	default:
		http.Error(w, "not found", 404)
	}
}

// settingsPaths are the endpoints handled by handleSettings (everything that is not DNS, VPN, account or backup). Adding an endpoint there means adding it here too.
var settingsPaths = map[string]bool{
	"wifi": true, "dhcp": true, "cell": true, "diag": true, "diag/run": true, "diag/report": true, "cert": true, "cert/renew": true, "cert/download": true, "cert/pillowforrt.crt": true,
	"ssh": true, "ssh/add": true, "ssh/delete": true, "sms": true, "devices": true, "devices/note": true, "graphs": true, "linkhist": true, "canary": true, "rogue-dhcp": true, "rogue-dhcp/allow": true, "arp": true, "tor": true, "tor/set": true, "tor/device": true, "tor/overvpn": true, "device/mode": true, "tor/test": true, "speed": true, "speed/set": true, "speed/run": true, "canary/set": true, "canary/ignore": true, "actions": true, "actions/set": true, "actions/delete": true, "actions/run": true, "events": true, "events/seen": true, "events/clear": true, "notify/set": true, "notify/clear": true, "notify/test": true, "devices/wake": true, "devices/watch": true,
	"system": true, "system/reboot": true, "system/stockadmin": true, "system/lanv6": true, "egress": true, "egress/set": true, "egress/allow": true, "egress/remove": true, "egress/service": true, "egress/httpupgrade": true,
	"dnscanary": true, "dnscanary/set": true, "macchurn": true, "torbypass": true, "beacon": true, "beacon/ignore": true, "dganxdomain": true, "tlssni": true, "tlscert": true, "lanannounce": true, "dnsxcheck": true, "dnsmitm": true, "dhcpfp": true, "ttl": true, "ttl/ignore": true, "admintrip": true, "steer": true, "steer/allow": true, "rebind": true, "rebind/set": true, "rebind/allow": true,
}

func isSettingsPath(path string) bool {
	return settingsPaths[path] || strings.HasPrefix(path, "wifi/") || strings.HasPrefix(path, "dhcp/") || strings.HasPrefix(path, "fw")
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	if path == "backup" || strings.HasPrefix(path, "backup/") {
		handleBackup(w, r, path)
		return
	}
	if path == "export" || strings.HasPrefix(path, "export/") {
		handleExportAPI(w, r, path)
		return
	}
	if path == "towers" || strings.HasPrefix(path, "towers/") {
		handleCellAPI(w, r, path)
		return
	}
	if path == "events/stream" {
		serveEventStream(w, r)
		return
	}
	if path == "tap" {
		handleTap(w, r)
		return
	}
	if strings.HasPrefix(path, "debug/") {
		handleDebug(w, r, path)
		return
	}
	if path == "bt" || strings.HasPrefix(path, "bt/") {
		handleBTAPI(w, r, path)
		return
	}
	if path == "search" || strings.HasPrefix(path, "search/") {
		handleSearchAPI(w, r, path)
		return
	}
	if isSettingsPath(path) {
		handleSettings(w, r, path)
		return
	}
	if path == "session" || strings.HasPrefix(path, "account/") {
		handleAccount(w, r, path)
		return
	}
	if path == "vpn" || strings.HasPrefix(path, "vpn/") {
		handleVPNAPI(w, r, path)
		return
	}
	if r.Method == http.MethodGet && path == "dns" {
		writeJSON(w, 200, dnsStatus())
		return
	}
	if r.Method == http.MethodGet && path == "dns/explain" && dnsProxy != nil {
		writeJSON(w, 200, dnsProxy.Filter.Explain(r.URL.Query().Get("ip"), r.URL.Query().Get("name"), time.Now()))
		return
	}
	if r.Method != http.MethodPost || dnsProxy == nil {
		http.Error(w, "not found", 404)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var body struct {
		Mode, Name, IP, Pattern, Note string
		Minutes                       int
		On                            bool
	}
	json.NewDecoder(r.Body).Decode(&body)
	f := dnsProxy.Filter
	var err error
	switch path {
	case "dns/mode":
		err = f.SetMode(body.Mode)
	case "dns/device":
		err = f.SetDeviceMode(body.IP, body.Mode)
	case "dns/pause":
		if body.Minutes <= 0 || body.Minutes > 24*60 {
			writeJSON(w, 400, map[string]string{"error": "minutes must be 1-1440"})
			return
		}
		f.Pause(time.Duration(body.Minutes) * time.Minute)
	case "dns/resume":
		f.Resume()
	case "dns/allow":
		err = f.AllowAdd(body.Name)
	case "dns/unallow":
		f.AllowRemove(body.Name)
	case "dns/list": // switch one block list on or off; a list never downloaded is fetched now
		if err = f.SetListEnabled(body.Name, body.On); err == nil && body.On {
			if sp, ok := listKnown(body.Name); ok && !f.hasList(body.Name) {
				go dnsUpdater.UpdateOne(sp, true)
			}
		}
	case "dns/custom":
		var n int
		if n, err = f.custom.Add(body.Pattern, body.IP, body.Note, body.Minutes); err == nil && n == 0 {
			err = errors.New("already in your rules")
		}
	case "dns/custom/remove":
		err = f.custom.Remove(body.Pattern, body.IP)
	case "dns/update":
		go dnsUpdater.UpdateAll(true)
	default:
		http.Error(w, "not found", 404)
		return
	}
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, dnsStatus())
}

// dnsSummary is the part of the DNS state that is safe to show anyone on the LAN: totals, no names, no devices.
func dnsSummary() map[string]any {
	if dnsProxy == nil {
		return map[string]any{"enabled": false}
	}
	sn := dnsProxy.Stats.Snapshot(0, 0)
	return map[string]any{"enabled": true, "mode": dnsProxy.Filter.Mode(), "upstream_mode": dnsProxy.Up.State().Mode,
		"queries": sn.Queries, "blocked": sn.Blocked, "errors": sn.Errors}
}

// certInstallDER returns the first certificate in a PEM file as DER, the form a phone installs.
func certInstallDER(p []byte) ([]byte, error) {
	for len(p) > 0 {
		var b *pem.Block
		b, p = pem.Decode(p)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			return b.Bytes, nil
		}
	}
	return nil, errors.New("no certificate in the file")
}
