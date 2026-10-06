package main

// Mullvad exit. One WireGuard key (one device slot on the account) runs as an in-process wireguard-go tunnel ("mullvad0"). Three things can use it, and all can be on at once:
//   - the whole house (default exit = mullvad), with a kill switch so a dead tunnel blocks instead of leaking;
//   - single devices (a per-device exit: Default / Direct / Mullvad), by MAC address (netfilter MARK + policy routing, vpn_policy.go);
//   - PAC-proxy users, whose connections tinyfwd dials through the tunnel (vpn_dial.go).
// The account number is typed into the web page once, used to register this Orbic as a device, and never stored or logged: only the device's own key and address are kept.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

var vpn *VPN // nil when the VPN is off (-vpn-dir empty); every method that matters is nil-safe

const (
	vpnIface   = "mullvad0"
	vpnMark    = "0x4d" // 77: packets with this mark are routed by table 77 (default via the tunnel)
	vpnTable   = "77"
	vpnMTU     = 1280
	mullvadAPI = "https://api.mullvad.net"
)

type vpnRelayPick struct {
	Country  string `json:"country"` // country code, e.g. "us"
	City     string `json:"city"`    // city code, e.g. "nyc"
	Hostname string `json:"hostname,omitempty"`
}

type vpnConfig struct {
	Registered  bool              `json:"registered"`
	DeviceID    string            `json:"device_id,omitempty"`
	DeviceName  string            `json:"device_name,omitempty"`
	PrivKey     string            `json:"priv_key,omitempty"` // base64, stays on the device (mode 0600)
	PubKey      string            `json:"pub_key,omitempty"`
	IPv4        string            `json:"ipv4,omitempty"` // the tunnel address Mullvad assigned, "10.x.y.z/32"
	IPv6        string            `json:"ipv6,omitempty"`
	Enabled     bool              `json:"enabled"` // the tunnel should be up
	Relay       vpnRelayPick      `json:"relay"`
	DefaultExit string            `json:"default_exit"`          // "direct" | "mullvad"
	DeviceExit  map[string]string `json:"device_exit,omitempty"` // device IPv4 -> "direct" | "mullvad" (absent = the default)
	KillSwitch  bool              `json:"kill_switch"`
	DNSViaVPN   bool              `json:"dns_via_vpn"`
}

func defaultVPNConfig() vpnConfig {
	return vpnConfig{DefaultExit: "direct", KillSwitch: true, DNSViaVPN: true, DeviceExit: map[string]string{}}
}

// ---- Mullvad API ----

type mullvadClient struct {
	base string
	hc   *http.Client
}

type mullvadDevice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IPv4 string `json:"ipv4_address"`
	IPv6 string `json:"ipv6_address"`
}

// apiError turns Mullvad's {"code","error"} reply into a plain sentence. The account number is never part of any message.
func apiError(status int, body []byte) error {
	var e struct{ Code, Error string }
	json.Unmarshal(body, &e)
	switch e.Code {
	case "INVALID_ACCOUNT":
		return errors.New("Mullvad does not recognise that account number")
	case "MAX_DEVICES_REACHED":
		return errors.New("this account already has the maximum number of devices (5): remove one at mullvad.net, then try again")
	case "KEY_ALREADY_IN_USE":
		return errors.New("that key is already registered")
	case "THROTTLED", "TOO_MANY_REQUESTS":
		return errors.New("Mullvad says too many attempts: wait a few minutes")
	}
	if e.Error != "" {
		return fmt.Errorf("Mullvad: %s", e.Error)
	}
	return fmt.Errorf("Mullvad answered HTTP %d", status)
}

func (c *mullvadClient) do(method, path, token string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, errors.New("could not reach Mullvad (is the uplink up?)")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

func (c *mullvadClient) token(account string) (string, error) {
	st, b, err := c.do("POST", "/auth/v1/token", "", map[string]string{"account_number": account})
	if err != nil {
		return "", err
	}
	if st != 200 {
		return "", apiError(st, b)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(b, &t) != nil || t.AccessToken == "" {
		return "", errors.New("Mullvad's token reply was not understood")
	}
	return t.AccessToken, nil
}

func (c *mullvadClient) createDevice(token, pub string) (mullvadDevice, error) {
	st, b, err := c.do("POST", "/accounts/v1/devices", token, map[string]any{"pubkey": pub, "hijack_dns": false})
	var d mullvadDevice
	if err != nil {
		return d, err
	}
	if st != 200 && st != 201 {
		return d, apiError(st, b)
	}
	if json.Unmarshal(b, &d) != nil || d.IPv4 == "" {
		return d, errors.New("Mullvad's device reply was not understood")
	}
	return d, nil
}

// createDeviceLegacy is the older form-style endpoint (account + public key -> "ipv4/32,ipv6/128"), used only if the device endpoint is missing.
func (c *mullvadClient) createDeviceLegacy(account, pub string) (mullvadDevice, error) {
	var d mullvadDevice
	req, _ := http.NewRequest("POST", c.base+"/wg/", strings.NewReader("account="+account+"&pubkey="+strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(pub)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return d, errors.New("could not reach Mullvad (is the uplink up?)")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return d, errors.New("Mullvad refused the registration: " + strings.TrimSpace(strings.ReplaceAll(string(b), account, "[account]")))
	}
	parts := strings.Split(strings.TrimSpace(string(b)), ",")
	if len(parts) < 1 || !strings.Contains(parts[0], "/") {
		return d, errors.New("Mullvad's registration reply was not understood")
	}
	d.IPv4 = parts[0]
	if len(parts) > 1 {
		d.IPv6 = parts[1]
	}
	return d, nil
}

func (c *mullvadClient) deleteDevice(token, id string) error {
	st, b, err := c.do("DELETE", "/accounts/v1/devices/"+id, token, nil)
	if err != nil {
		return err
	}
	if st != 200 && st != 204 && st != 404 {
		return apiError(st, b)
	}
	return nil
}

// ---- relays ----

type vpnRelay struct {
	Country, CountryName, City, CityName, Hostname, IPv4, PubKey string
}

func parseRelays(b []byte) ([]vpnRelay, error) {
	var d struct {
		Countries []struct {
			Name, Code string
			Cities     []struct {
				Name, Code string
				Relays     []struct {
					Hostname string `json:"hostname"`
					IPv4     string `json:"ipv4_addr_in"`
					PubKey   string `json:"public_key"`
				}
			}
		}
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	var out []vpnRelay
	for _, c := range d.Countries {
		for _, ci := range c.Cities {
			for _, r := range ci.Relays {
				if r.Hostname != "" && r.IPv4 != "" && r.PubKey != "" {
					out = append(out, vpnRelay{c.Code, c.Name, ci.Code, ci.Name, r.Hostname, r.IPv4, r.PubKey})
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("the relay list was empty")
	}
	return out, nil
}

type vpnCity struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Relays int    `json:"relays"`
}
type vpnCountry struct {
	Code   string    `json:"code"`
	Name   string    `json:"name"`
	Cities []vpnCity `json:"cities"`
}

func locations(rs []vpnRelay) []vpnCountry {
	type key struct{ country, city string }
	counts := map[key]int{}
	cnames := map[string]string{}
	citynames := map[key]string{}
	for _, r := range rs {
		k := key{r.Country, r.City}
		counts[k]++
		cnames[r.Country] = r.CountryName
		citynames[k] = r.CityName
	}
	byCountry := map[string]*vpnCountry{}
	for k, n := range counts {
		c := byCountry[k.country]
		if c == nil {
			c = &vpnCountry{Code: k.country, Name: cnames[k.country]}
			byCountry[k.country] = c
		}
		c.Cities = append(c.Cities, vpnCity{Code: k.city, Name: citynames[k], Relays: n})
	}
	out := make([]vpnCountry, 0, len(byCountry))
	for _, c := range byCountry {
		sort.Slice(c.Cities, func(i, j int) bool { return c.Cities[i].Name < c.Cities[j].Name })
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- keys ----

func newWGKey() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], p)
	return
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ---- the VPN object ----

type VPN struct {
	mu       sync.Mutex
	dir      string
	cfg      vpnConfig
	api      *mullvadClient
	tun      *tunnel
	relays   []vpnRelay
	relayAt  time.Time
	fetching bool
	lastErr  string
	canon    func(string) string // an IPv6 client address -> its device's IPv4 address
	macOf    func(ip string) string
	applyFn  func(plan exitPlan) error // test hook: how rules are applied
}

func NewVPN(dir string, hc *http.Client) *VPN {
	return &VPN{dir: dir, cfg: defaultVPNConfig(), api: &mullvadClient{base: mullvadAPI, hc: hc}, tun: &tunnel{}}
}

func (v *VPN) path() string { return filepath.Join(v.dir, "state.json") }

func (v *VPN) Load() {
	os.MkdirAll(v.dir, 0o700)
	b, err := os.ReadFile(v.path())
	if err != nil {
		return
	}
	c := defaultVPNConfig()
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if c.DefaultExit != "mullvad" {
		c.DefaultExit = "direct"
	}
	if c.DeviceExit == nil {
		c.DeviceExit = map[string]string{}
	}
	v.mu.Lock()
	v.cfg = c
	v.mu.Unlock()
}

// saveLocked writes the state atomically with mode 0600 (it holds the device's private key).
func (v *VPN) saveLocked() {
	os.MkdirAll(v.dir, 0o700)
	b, _ := json.MarshalIndent(v.cfg, "", " ")
	tmp := v.path() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, v.path())
	}
}

func validExit(e string) bool { return e == "direct" || e == "mullvad" }

// ExitFor says which exit a LAN client uses right now: "mullvad" or "direct".
func (v *VPN) ExitFor(client string) string {
	if v == nil {
		return "direct"
	}
	if v.canon != nil {
		client = v.canon(client)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.cfg.Registered {
		return "direct"
	}
	if e, ok := v.cfg.DeviceExit[client]; ok {
		return e
	}
	if strings.HasPrefix(client, "127.") || client == "::1" || client == "" {
		return "direct" // the Orbic's own queries never take the exit
	}
	return v.cfg.DefaultExit
}

func (v *VPN) fail(err error) error {
	v.mu.Lock()
	v.lastErr = err.Error()
	v.mu.Unlock()
	return err
}

// Register creates this Orbic's Mullvad device. The account number is used for the calls and then dropped.
func (v *VPN) Register(account string) error {
	account = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, account)
	if len(account) != 16 {
		return v.fail(errors.New("a Mullvad account number is 16 digits"))
	}
	v.mu.Lock()
	if v.cfg.Registered {
		v.mu.Unlock()
		return v.fail(errors.New("this Orbic is already registered; remove the device first"))
	}
	v.mu.Unlock()
	priv, pub, err := newWGKey()
	if err != nil {
		return v.fail(err)
	}
	tok, err := v.api.token(account)
	if err != nil {
		return v.fail(err)
	}
	d, err := v.api.createDevice(tok, b64(pub[:]))
	if err != nil {
		var legacy bool
		if strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "HTTP 405") {
			legacy = true
		}
		if !legacy {
			return v.fail(err)
		}
		if d, err = v.api.createDeviceLegacy(account, b64(pub[:])); err != nil {
			return v.fail(err)
		}
	}
	v.mu.Lock()
	v.cfg.Registered, v.cfg.DeviceID, v.cfg.DeviceName = true, d.ID, d.Name
	v.cfg.PrivKey, v.cfg.PubKey, v.cfg.IPv4, v.cfg.IPv6 = b64(priv[:]), b64(pub[:]), d.IPv4, d.IPv6
	v.lastErr = ""
	v.saveLocked()
	v.mu.Unlock()
	return nil
}

// Remove deletes the device at Mullvad (frees the slot) and forgets the key. The account number is needed again for that.
func (v *VPN) Remove(account string) error {
	account = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, account)
	v.mu.Lock()
	id, reg := v.cfg.DeviceID, v.cfg.Registered
	v.mu.Unlock()
	if !reg {
		return errors.New("nothing is registered")
	}
	if id != "" {
		if len(account) != 16 {
			return v.fail(errors.New("enter the account number again to remove the device from your account"))
		}
		tok, err := v.api.token(account)
		if err != nil {
			return v.fail(err)
		}
		if err := v.api.deleteDevice(tok, id); err != nil {
			return v.fail(err)
		}
	}
	v.tun.stop()
	v.mu.Lock()
	keep := v.cfg
	v.cfg = defaultVPNConfig()
	v.cfg.KillSwitch, v.cfg.DNSViaVPN = keep.KillSwitch, keep.DNSViaVPN
	v.lastErr = ""
	v.saveLocked()
	v.mu.Unlock()
	v.Reconcile()
	return nil
}

func (v *VPN) update(f func(c *vpnConfig)) {
	v.mu.Lock()
	f(&v.cfg)
	v.saveLocked()
	v.mu.Unlock()
	v.Reconcile()
}

func (v *VPN) SetEnabled(on bool) error {
	v.mu.Lock()
	reg := v.cfg.Registered
	v.mu.Unlock()
	if on && !reg {
		return errors.New("register this Orbic with your Mullvad account first")
	}
	v.update(func(c *vpnConfig) { c.Enabled = on })
	if !on {
		v.tun.stop()
		v.Reconcile()
	}
	return nil
}

func (v *VPN) SetRelay(country, city string) error {
	v.mu.Lock()
	rs := v.relays
	v.mu.Unlock()
	if len(rs) > 0 {
		ok := false
		for _, r := range rs {
			if r.Country == country && r.City == city {
				ok = true
				break
			}
		}
		if !ok {
			return errors.New("no such location")
		}
	}
	v.update(func(c *vpnConfig) { c.Relay = vpnRelayPick{Country: country, City: city} })
	v.tun.stop() // the monitor loop brings it up again on the new relay
	return nil
}

func (v *VPN) SetDefaultExit(e string) error {
	if !validExit(e) {
		return errors.New("exit must be direct or mullvad")
	}
	v.mu.Lock()
	if e == "mullvad" && !v.cfg.Registered {
		v.mu.Unlock()
		return errors.New("register this Orbic with your Mullvad account first")
	}
	v.mu.Unlock()
	v.update(func(c *vpnConfig) { c.DefaultExit = e })
	return nil
}

func (v *VPN) SetDeviceExit(ip, e string) error {
	if ip == "" || strings.ContainsAny(ip, " \n\"") {
		return errors.New("not a device address")
	}
	if e != "" && e != "default" && !validExit(e) {
		return errors.New("exit must be default, direct or mullvad")
	}
	v.mu.Lock()
	if e == "mullvad" && !v.cfg.Registered {
		v.mu.Unlock()
		return errors.New("register this Orbic with your Mullvad account first")
	}
	if _, had := v.cfg.DeviceExit[ip]; !had && len(v.cfg.DeviceExit) >= 64 && e != "" && e != "default" {
		v.mu.Unlock()
		return errors.New("too many device overrides")
	}
	v.mu.Unlock()
	v.update(func(c *vpnConfig) {
		if e == "" || e == "default" {
			delete(c.DeviceExit, ip)
		} else {
			c.DeviceExit[ip] = e
		}
	})
	return nil
}

func (v *VPN) SetKillSwitch(on bool) { v.update(func(c *vpnConfig) { c.KillSwitch = on }) }
func (v *VPN) SetDNSViaVPN(on bool)  { v.update(func(c *vpnConfig) { c.DNSViaVPN = on }) }

// Panic sends everything direct at once (the tunnel stays up).
func (v *VPN) Panic() {
	v.update(func(c *vpnConfig) { c.DefaultExit = "direct"; c.DeviceExit = map[string]string{} })
}

// vpnStatus is the public view: it never includes the key or the account.
type vpnStatus struct {
	Registered bool              `json:"registered"`
	DeviceName string            `json:"device_name,omitempty"`
	Address    string            `json:"address,omitempty"`
	Enabled    bool              `json:"enabled"`
	Up         bool              `json:"up"`
	Relay      string            `json:"relay,omitempty"`
	RelayPick  vpnRelayPick      `json:"relay_pick"`
	HandshakeS int64             `json:"handshake_age_s"`
	Rx         uint64            `json:"rx_bytes"`
	Tx         uint64            `json:"tx_bytes"`
	UpSince    *time.Time        `json:"up_since,omitempty"`
	Default    string            `json:"default_exit"`
	DeviceExit map[string]string `json:"device_exit"`
	KillSwitch bool              `json:"kill_switch"`
	DNSViaVPN  bool              `json:"dns_via_vpn"`
	Error      string            `json:"error,omitempty"`
	Locations  []vpnCountry      `json:"locations"`
}

func (v *VPN) Status() vpnStatus {
	up, relay, since, hs, rx, tx := v.tun.snapshot()
	v.mu.Lock()
	defer v.mu.Unlock()
	st := vpnStatus{Registered: v.cfg.Registered, DeviceName: v.cfg.DeviceName, Address: v.cfg.IPv4, Enabled: v.cfg.Enabled, Up: up, Relay: relay, RelayPick: v.cfg.Relay,
		HandshakeS: hs, Rx: rx, Tx: tx, Default: v.cfg.DefaultExit, DeviceExit: map[string]string{}, KillSwitch: v.cfg.KillSwitch, DNSViaVPN: v.cfg.DNSViaVPN, Error: v.lastErr}
	if up && !since.IsZero() {
		st.UpSince = &since
	}
	st.Locations = []vpnCountry{}
	for k, e := range v.cfg.DeviceExit {
		st.DeviceExit[k] = e
	}
	if len(v.relays) > 0 {
		st.Locations = locations(v.relays)
	}
	return st
}

// ---- relay choice and connecting ----

func (v *VPN) fetchRelays() error {
	req, _ := http.NewRequest("GET", v.api.base+"/public/relays/wireguard/v1/", nil)
	resp, err := v.api.hc.Do(req)
	if err != nil {
		return errors.New("could not fetch Mullvad's relay list (is the uplink up?)")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("the relay list answered HTTP %d", resp.StatusCode)
	}
	rs, err := parseRelays(b)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.relays, v.relayAt = rs, time.Now()
	v.mu.Unlock()
	return nil
}

// EnsureRelays loads the relay list in the background when it is missing or old (the web page's location menus come from it).
func (v *VPN) EnsureRelays() {
	v.mu.Lock()
	need := (len(v.relays) == 0 || time.Since(v.relayAt) > 12*time.Hour) && !v.fetching
	if need {
		v.fetching = true
	}
	v.mu.Unlock()
	if need {
		go func() {
			v.fetchRelays()
			v.mu.Lock()
			v.fetching = false
			v.mu.Unlock()
		}()
	}
}

// pingMS measures a relay's round trip with the system ping (relays answer ICMP); a failure counts as very slow.
func pingMS(ip string) float64 {
	out, err := run("ping", "-c", "1", "-W", "1", ip)
	if err != nil {
		return 9999
	}
	i := strings.Index(out, "time=")
	if i < 0 {
		return 9999
	}
	f := strings.Fields(out[i+5:])
	if len(f) == 0 {
		return 9999
	}
	var ms float64
	fmt.Sscanf(strings.TrimSuffix(f[0], "ms"), "%f", &ms)
	return ms
}

// candidates returns the relays of the chosen city, fastest first (all of them are tried in turn on repeated failures).
func (v *VPN) candidates(measure bool) ([]vpnRelay, error) {
	v.mu.Lock()
	rs, pick := v.relays, v.cfg.Relay
	v.mu.Unlock()
	if len(rs) == 0 {
		return nil, errors.New("no relay list yet")
	}
	var c []vpnRelay
	for _, r := range rs {
		if r.Country == pick.Country && r.City == pick.City {
			c = append(c, r)
		}
	}
	if len(c) == 0 { // nothing chosen yet: a reasonable default so "connect" works at once
		for _, r := range rs {
			if r.Country == "us" && r.City == "nyc" {
				c = append(c, r)
			}
		}
	}
	if len(c) == 0 {
		c = rs[:1]
	}
	if measure && len(c) > 1 {
		if len(c) > 12 {
			c = c[:12]
		}
		ms := make([]float64, len(c))
		var wg sync.WaitGroup
		for i := range c {
			wg.Add(1)
			go func(i int) { defer wg.Done(); ms[i] = pingMS(c[i].IPv4) }(i)
		}
		wg.Wait()
		idx := make([]int, len(c))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool { return ms[idx[a]] < ms[idx[b]] })
		sorted := make([]vpnRelay, len(c))
		for i, j := range idx {
			sorted[i] = c[j]
		}
		c = sorted
	}
	return c, nil
}

func (v *VPN) connect(attempt int) error {
	v.mu.Lock()
	need := len(v.relays) == 0 || time.Since(v.relayAt) > 12*time.Hour
	v.mu.Unlock()
	if need {
		if err := v.fetchRelays(); err != nil {
			v.mu.Lock()
			have := len(v.relays) > 0
			v.mu.Unlock()
			if !have {
				return err
			}
		}
	}
	c, err := v.candidates(true)
	if err != nil {
		return err
	}
	v.mu.Lock()
	cfg := v.cfg
	v.mu.Unlock()
	return v.tun.start(cfg, c[attempt%len(c)])
}
