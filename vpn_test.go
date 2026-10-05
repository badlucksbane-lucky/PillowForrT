package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

const testAccount = "1234567890123456"

// fakeMullvad is a stand-in for api.mullvad.net.
type fakeMullvad struct {
	*httptest.Server
	devices   map[string]string // id -> pubkey
	failCode  string            // make /accounts/v1/devices fail with this code
	legacy    bool              // 404 the device endpoint, answer /wg/ instead
	deleted   []string
	sawAcct   bool
	lastToken string
}

func newFakeMullvad(t *testing.T) *fakeMullvad {
	f := &fakeMullvad{devices: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/token", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			AccountNumber string `json:"account_number"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if b.AccountNumber != testAccount {
			w.WriteHeader(400)
			w.Write([]byte(`{"code":"INVALID_ACCOUNT","error":"Bad account number"}`))
			return
		}
		f.sawAcct = true
		w.Write([]byte(`{"access_token":"tok123","expiry":"2099-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/accounts/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		if f.legacy {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.WriteHeader(401)
			return
		}
		if f.failCode != "" {
			w.WriteHeader(400)
			w.Write([]byte(`{"code":"` + f.failCode + `","error":"x"}`))
			return
		}
		var b struct {
			Pubkey string `json:"pubkey"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		f.devices["dev-1"] = b.Pubkey
		w.WriteHeader(201)
		w.Write([]byte(`{"id":"dev-1","name":"quiet-otter","pubkey":"` + b.Pubkey + `","ipv4_address":"10.66.1.2/32","ipv6_address":"fc00:bbbb:bbbb:bb01::2:3/128"}`))
	})
	mux.HandleFunc("/accounts/v1/devices/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && r.Header.Get("Authorization") == "Bearer tok123" {
			f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/accounts/v1/devices/"))
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(401)
	})
	mux.HandleFunc("/wg/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "account="+testAccount) {
			w.WriteHeader(400)
			w.Write([]byte("Account does not exist"))
			return
		}
		w.Write([]byte("10.66.9.9/32,fc00:bbbb:bbbb:bb01::9:9/128"))
	})
	mux.HandleFunc("/public/relays/wireguard/v1/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(relayJSON))
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

const relayJSON = `{"countries":[
 {"name":"USA","code":"us","cities":[
   {"name":"New York, NY","code":"nyc","relays":[
     {"hostname":"us-nyc-wg-001","ipv4_addr_in":"198.51.100.1","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","multihop_port":3000},
     {"hostname":"us-nyc-wg-002","ipv4_addr_in":"198.51.100.2","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","multihop_port":3001}]},
   {"name":"Chicago, IL","code":"chi","relays":[
     {"hostname":"us-chi-wg-001","ipv4_addr_in":"198.51.100.3","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","multihop_port":3002}]}]},
 {"name":"Sweden","code":"se","cities":[{"name":"Malmo","code":"mma","relays":[
     {"hostname":"se-mma-wg-001","ipv4_addr_in":"198.51.100.4","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
     {"hostname":"","ipv4_addr_in":"198.51.100.5","public_key":"AAAA"}]}]}]}`

func testVPN(t *testing.T, f *fakeMullvad) (*VPN, *[]exitPlan) {
	v := NewVPN(filepath.Join(t.TempDir(), "vpn"), http.DefaultClient)
	v.api.base = f.URL
	plans := &[]exitPlan{}
	v.applyFn = func(p exitPlan) error { *plans = append(*plans, p); return nil }
	macs := map[string]string{"192.168.1.40": "00:00:5e:00:53:04", "192.168.1.20": "00:00:5e:00:53:08", "192.168.1.2": "00:00:5e:00:53:03"}
	v.macOf = func(ip string) string { return macs[ip] }
	return v, plans
}

func TestKeyGen(t *testing.T) {
	priv, pub, err := newWGKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv[0]&7 != 0 || priv[31]&0x80 != 0 || priv[31]&0x40 == 0 {
		t.Error("private key not clamped")
	}
	want, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	if string(want) != string(pub[:]) || len(b64(pub[:])) != 44 {
		t.Error("public key does not match the private key")
	}
	if _, err := hexKey(b64(priv[:])); err != nil {
		t.Error(err)
	}
	if _, err := hexKey("not-base64"); err == nil {
		t.Error("garbage accepted as a key")
	}
}

func TestRegisterAndRemove(t *testing.T) {
	f := newFakeMullvad(t)
	v, _ := testVPN(t, f)
	if err := v.Register("1234"); err == nil {
		t.Error("a short account number was accepted")
	}
	if err := v.Register("0000000000000000"); err == nil || !strings.Contains(err.Error(), "does not recognise") {
		t.Errorf("bad account: %v", err)
	}
	f.failCode = "MAX_DEVICES_REACHED"
	if err := v.Register(testAccount); err == nil || !strings.Contains(err.Error(), "maximum number of devices") {
		t.Errorf("device limit: %v", err)
	}
	f.failCode = ""
	if err := v.Register("1234 5678 9012 3456"); err != nil { // spaces are fine
		t.Fatal(err)
	}
	if err := v.Register(testAccount); err == nil {
		t.Error("registered twice")
	}
	st := v.Status()
	if !st.Registered || st.DeviceName != "quiet-otter" || st.Address != "10.66.1.2/32" {
		t.Errorf("status %+v", st)
	}
	jb, _ := json.Marshal(st)
	raw, _ := os.ReadFile(v.path())
	if strings.Contains(string(jb), v.cfg.PrivKey) || strings.Contains(string(raw), testAccount) || strings.Contains(string(jb), testAccount) {
		t.Error("a secret leaked into the public status or the saved account number")
	}
	if !strings.Contains(string(raw), v.cfg.PrivKey) {
		t.Error("the device key was not saved")
	}
	if fi, _ := os.Stat(v.path()); fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v", fi.Mode().Perm())
	}
	if f.devices["dev-1"] != v.cfg.PubKey {
		t.Error("Mullvad was given a different public key")
	}
	w := NewVPN(v.dir, http.DefaultClient) // survives a restart
	w.Load()
	if !w.cfg.Registered || w.cfg.PrivKey != v.cfg.PrivKey {
		t.Error("state not reloaded")
	}
	if err := v.Remove(""); err == nil {
		t.Error("removal without the account number was accepted")
	}
	if err := v.Remove(testAccount); err != nil {
		t.Fatal(err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "dev-1" || v.Status().Registered {
		t.Errorf("remove: deleted %v status %+v", f.deleted, v.Status())
	}
}

func TestRegisterLegacyFallback(t *testing.T) {
	f := newFakeMullvad(t)
	f.legacy = true
	v, _ := testVPN(t, f)
	if err := v.Register(testAccount); err != nil {
		t.Fatal(err)
	}
	if v.cfg.IPv4 != "10.66.9.9/32" || !strings.HasPrefix(v.cfg.IPv6, "fc00:") {
		t.Errorf("legacy addresses: %q %q", v.cfg.IPv4, v.cfg.IPv6)
	}
}

func TestExitFor(t *testing.T) {
	f := newFakeMullvad(t)
	v, _ := testVPN(t, f)
	if v.ExitFor("192.168.1.40") != "direct" {
		t.Error("unregistered must be direct")
	}
	var nilVPN *VPN
	if nilVPN.ExitFor("1.2.3.4") != "direct" || nilVPN.UseVPNDNS("1.2.3.4") {
		t.Error("nil VPN must be direct")
	}
	v.Register(testAccount)
	if err := v.SetDefaultExit("bogus"); err == nil {
		t.Error("bad exit accepted")
	}
	v.SetDefaultExit("mullvad")
	v.SetDeviceExit("192.168.1.2", "direct")
	for ip, want := range map[string]string{"192.168.1.40": "mullvad", "192.168.1.2": "direct", "127.0.0.1": "direct", "": "direct"} {
		if got := v.ExitFor(ip); got != want {
			t.Errorf("ExitFor(%q) = %s, want %s", ip, got, want)
		}
	}
	v.canon = func(ip string) string {
		if ip == "fe80::1" {
			return "192.168.1.2"
		}
		return ip
	}
	if v.ExitFor("fe80::1") != "direct" {
		t.Error("an IPv6 client was not mapped to its device's override")
	}
	v.SetDefaultExit("direct")
	v.SetDeviceExit("192.168.1.40", "mullvad")
	if v.ExitFor("192.168.1.40") != "mullvad" || v.ExitFor("192.168.1.20") != "direct" {
		t.Error("per-device exit")
	}
	v.SetDeviceExit("192.168.1.40", "default")
	if v.ExitFor("192.168.1.40") != "direct" {
		t.Error("default did not clear the override")
	}
	v.SetDeviceExit("192.168.1.40", "mullvad")
	v.Panic()
	if v.ExitFor("192.168.1.40") != "direct" || v.cfg.DefaultExit != "direct" || len(v.cfg.DeviceExit) != 0 {
		t.Error("panic did not send everything direct")
	}
	if err := v.SetDeviceExit("bad ip", "mullvad"); err == nil {
		t.Error("bad address accepted")
	}
}

func TestUnregisteredCannotSelectVPN(t *testing.T) {
	v, _ := testVPN(t, newFakeMullvad(t))
	if v.SetDefaultExit("mullvad") == nil || v.SetDeviceExit("192.168.1.40", "mullvad") == nil || v.SetEnabled(true) == nil {
		t.Error("the VPN could be selected before registering")
	}
}

func TestPlanRules(t *testing.T) {
	has := func(s, sub string) bool { return strings.Contains(s, sub) }
	// whole house, tunnel up, kill switch on, the companion computer exempt
	m, f, s6 := planRules(exitPlan{Active: true, DefaultVPN: true, DirectMacs: []string{"00:00:5e:00:53:03"}, KillSwitch: true, TunnelUp: true})
	if !has(m, "-A HS_EXIT -m mac --mac-source 00:00:5e:00:53:03 -j RETURN\n-A HS_EXIT -j MARK --set-mark 0x4d") {
		t.Errorf("mangle:\n%s", m)
	}
	if !has(f, "-A HS_KILL -i bridge0 -o rmnet_data+ -j DROP") || !has(f, "--mac-source 00:00:5e:00:53:03 -j RETURN") || !has(s6, "-A HS_V6 -i bridge0 -j REJECT") {
		t.Errorf("filter/v6:\n%s\n%s", f, s6)
	}
	// the exemption comes BEFORE the catch-all in every chain
	if strings.Index(f, "RETURN") > strings.Index(f, "DROP") || strings.Index(s6, "RETURN") > strings.Index(s6, "REJECT") {
		t.Error("exemption after the catch-all")
	}
	// per device, tunnel up
	m, f, s6 = planRules(exitPlan{Active: true, VPNMacs: []string{"00:00:5e:00:53:04"}, KillSwitch: true, TunnelUp: true})
	if !has(m, "--mac-source 00:00:5e:00:53:04 -j MARK --set-mark 0x4d") || has(m, "-A HS_EXIT -j MARK") ||
		!has(f, "-o rmnet_data+ -m mac --mac-source 00:00:5e:00:53:04 -j DROP") || !has(s6, "--mac-source 00:00:5e:00:53:04 -j REJECT") {
		t.Errorf("per-device:\n%s\n%s\n%s", m, f, s6)
	}
	// tunnel down + kill switch: no marks (nothing to route to), but the kill rule blocks the cellular path
	m, f, _ = planRules(exitPlan{Active: true, VPNMacs: []string{"00:00:5e:00:53:04"}, KillSwitch: true, TunnelUp: false})
	if has(m, "MARK") || !has(f, "DROP") {
		t.Errorf("down+killswitch:\n%s\n%s", m, f)
	}
	// tunnel down, kill switch off: nothing blocks, nothing marks (traffic simply goes direct)
	m, f, _ = planRules(exitPlan{Active: true, DefaultVPN: true, KillSwitch: false, TunnelUp: false})
	if has(m, "MARK") || has(f, "DROP") {
		t.Errorf("down, no killswitch:\n%s\n%s", m, f)
	}
	// nobody uses the tunnel: all three chains are declared (so they get emptied) and hold nothing
	m, f, s6 = planRules(exitPlan{})
	for _, r := range []string{m, f, s6} {
		if strings.Contains(r, "-A ") || !strings.HasSuffix(r, "COMMIT\n") || !strings.Contains(r, "- [0:0]") {
			t.Errorf("idle plan not empty:\n%s", r)
		}
	}
}

func TestBuildPlan(t *testing.T) {
	f := newFakeMullvad(t)
	v, plans := testVPN(t, f)
	v.Register(testAccount)
	v.SetDeviceExit("192.168.1.40", "mullvad")
	v.SetDeviceExit("192.168.1.2", "direct")
	v.SetDeviceExit("192.168.1.99", "mullvad") // asleep / unknown MAC: skipped, not an error
	p := (*plans)[len(*plans)-1]
	if !p.Active || p.DefaultVPN || len(p.VPNMacs) != 1 || p.VPNMacs[0] != "00:00:5e:00:53:04" || len(p.DirectMacs) != 1 || !p.KillSwitch || p.TunnelUp {
		t.Errorf("plan %+v", p)
	}
	v.SetKillSwitch(false)
	if p := (*plans)[len(*plans)-1]; p.KillSwitch {
		t.Error("kill switch not turned off")
	}
}

func TestRelays(t *testing.T) {
	rs, err := parseRelays([]byte(relayJSON))
	if err != nil || len(rs) != 4 { // the relay without a hostname is dropped
		t.Fatalf("%d relays, %v", len(rs), err)
	}
	if _, err := parseRelays([]byte(`{"countries":[]}`)); err == nil {
		t.Error("an empty list was accepted")
	}
	loc := locations(rs)
	if len(loc) != 2 || loc[0].Name != "Sweden" || loc[1].Code != "us" || len(loc[1].Cities) != 2 || loc[1].Cities[1].Code != "nyc" && loc[1].Cities[0].Code != "nyc" {
		t.Errorf("locations %+v", loc)
	}
	for _, c := range loc[1].Cities {
		if c.Code == "nyc" && c.Relays != 2 {
			t.Errorf("nyc has %d relays", c.Relays)
		}
	}
	f := newFakeMullvad(t)
	v, _ := testVPN(t, f)
	if err := v.fetchRelays(); err != nil {
		t.Fatal(err)
	}
	v.Register(testAccount)
	if err := v.SetRelay("us", "nyc"); err != nil {
		t.Error(err)
	}
	if err := v.SetRelay("xx", "yyy"); err == nil {
		t.Error("an unknown location was accepted")
	}
	c, err := v.candidates(false)
	if err != nil || len(c) != 2 || c[0].Hostname != "us-nyc-wg-001" {
		t.Errorf("candidates %+v %v", c, err)
	}
	if st := v.Status(); len(st.Locations) != 2 {
		t.Error("the status lacks the location list")
	}
}

func TestMacMap(t *testing.T) {
	arp := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.20    0x1         0x2         00:00:5e:00:53:08     *        bridge0\n"
	leases := "1790 00:00:5e:00:53:06 192.168.1.30 phone-a 01:22\n1790 aa:aa:aa:aa:aa:aa 192.168.1.20 stale *\nduid 00:01\n"
	m := macMapFromARP(arp, leases)
	if m["192.168.1.20"] != "00:00:5e:00:53:08" || m["192.168.1.30"] != "00:00:5e:00:53:06" || len(m) != 2 {
		t.Errorf("%v", m)
	}
}

func TestKillSwitchBlocksProxyAndDNS(t *testing.T) {
	f := newFakeMullvad(t)
	v, _ := testVPN(t, f)
	v.Register(testAccount)
	v.SetDefaultExit("mullvad") // tunnel is not up in a test
	if _, err := v.DialFor(nil, "192.168.1.40", "tcp", "example.com:443"); err != errKillSwitch {
		t.Errorf("dial with the tunnel down: %v", err)
	}
	if _, err := v.TransportFor("192.168.1.40"); err != errKillSwitch {
		t.Errorf("transport with the tunnel down: %v", err)
	}
	if tr, err := v.TransportFor("127.0.0.1"); err != nil || tr != transport {
		t.Error("the Orbic's own traffic must stay direct")
	}
	// DNS: a VPN device's lookup with the tunnel down fails closed and never reaches Quad9
	doh, pool := newFakeDoH(t)
	plain, plainHits := fakePlain(t)
	p := testProxy(t, doh, pool, plain)
	p.VPN = v
	ecs := opt(8, 0, 1, 32, 0, 192, 168, 1, 40)
	r := p.Handle(queryWithOpt("example.org", ecs))
	if rcodeOf(r) != 2 || doh.hits.Load() != 0 || plainHits.Load() != 0 {
		t.Errorf("rcode %d, upstream hits doh=%d plain=%d (a VPN device's DNS leaked)", rcodeOf(r), doh.hits.Load(), plainHits.Load())
	}
	other := opt(8, 0, 1, 32, 0, 192, 168, 1, 2)
	v.SetDeviceExit("192.168.1.2", "direct")
	if r := p.Handle(queryWithOpt("example.org", other)); rcodeOf(r) != 0 || doh.hits.Load() != 1 {
		t.Error("a direct device's DNS must still use the normal path")
	}
}
