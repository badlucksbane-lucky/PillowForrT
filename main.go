// tinyfwd - a minimal forward HTTP/HTTPS proxy, Squid-style, listening on :3128, that is
// also the Orbic hotspot's vantage-node daemon (status.json, heartbeat, usage counters;
// see status.go and stats.go).
//
//   - Plain HTTP: forwards absolute-URI requests to the origin and streams the reply.
//   - HTTPS / anything: handles CONNECT by opening a raw TCP tunnel (no interception).
//   - Access control: only clients inside the allowed CIDRs may use it (default: the
//     RFC1918 / loopback ranges), so leaving it bound to 0.0.0.0 is still LAN-only.
//
// No caching, no rewriting, no TLS MITM - it just passes bytes through.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	listenAddr = flag.String("listen", ":3128", "address:port to listen on")
	allowFlag  = flag.String("allow", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "comma-separated CIDRs allowed to use the proxy")
	verbose    = flag.Bool("v", false, "log every request")
	ipv4Only   = flag.Bool("4", true, "force IPv4 for all upstream connections (the Orbic's cellular link has no IPv6)")
	pacFile    = flag.String("pac", "", "path to a PAC file to serve at /wpad.dat and /proxy.pac (empty = serve a built-in one)")
	proxyHost  = flag.String("proxy-host", "192.168.1.1:3128", "host:port advertised inside the built-in PAC")
	allowNets  []*net.IPNet

	statePath       = flag.String("state", "", "file that persists the usage counters across reboots (empty = off)")
	cycleDay        = flag.Int("cycle-day", 1, "day of month the data plan's billing cycle starts (1-28)")
	capGB           = flag.Float64("cap-gb", 0, "data plan cap in GB for the budget figures (0 = unknown)")
	rmnetIface      = flag.String("rmnet", "rmnet_data0", "cellular interface whose byte counters measure the data plan")
	probeTarget     = flag.String("probe", "1.1.1.1:443", "host:port the uplink probe connects to every 30 s")
	beatTokenFile   = flag.String("beat-token-file", "", "file holding the shared token the companion computer sends with /beat (empty = the heartbeat endpoint is off, the default)")
	silentAfter     = flag.Duration("silent-after", 10*time.Minute, "no heartbeat for this long = the companion computer is silent")
	eventHook       = flag.String("on-event", "", "executable run as `hook silent` / `hook recover` when the heartbeat stops / returns")
	dnsListen       = flag.String("dns-listen", "", "address for the DNS filter stub, e.g. 127.0.0.1:5354 (empty = DNS filter off)")
	dnsDir          = flag.String("dns-dir", "/data/dnsfilter", "directory for the filter's lists, allow-list and state")
	dnsPlainAfter   = flag.Duration("dns-plain-after", 60*time.Second, "how long encrypted DNS must keep failing before queries may go out as plain DNS (SERVFAIL meanwhile); 0 = at the first failure, negative = never")
	dnsDoH          = flag.String("dns-doh", "https://9.9.9.9/dns-query,https://1.1.1.1/dns-query,https://149.112.112.112/dns-query", "comma-separated DoH endpoints (IP literals, no bootstrap DNS)")
	dnsResolv       = flag.String("dns-resolv", "/etc/resolv.conf", "file with the carrier's plain resolvers, the fallback when DoH is down")
	leasesFile      = flag.String("leases", "/data/dnsmasq.leases", "dnsmasq lease file (device names for the web page)")
	dhcpHostsFile   = flag.String("dhcp-hosts", "/data/dhcp_hosts", "dnsmasq reservations file (device names for the web page)")
	macBlockFile    = flag.String("mac-block", "/data/proxy/macblock.list", "the Wi-Fi block list (one MAC per line)")
	fwFile          = flag.String("fw-rules", "/data/proxy/fw.json", "our firewall rules: blocked destinations, internet schedules and pauses")
	schedTZ         = flag.String("tz", "UTC", "time zone for internet schedules and the clock the page shows (the stock firmware is fixed at Eastern)")
	smsDBFile       = flag.String("sms-db", "/usrdata/data/usr/cpe.db", "the stock firmware's SQLite file holding the SMS tables (read-only, via a copy)")
	sshDir          = flag.String("ssh-dir", "/data/dropbear/ssh", "dropbear's -D directory (authorized_keys, host key)")
	stockAdminFlag  = flag.String("stock-admin-flag", "/data/proxy/stockadmin.off", "when this file exists the stock admin is switched off for the network (the page sets it)")
	lanV6Flag       = flag.String("lan-v6-flag", "/data/proxy/lanv6.on", "LAN IPv6 is ON only while this file exists; without it (the default) router advertisements are dropped and a withdraw is sent (the page sets it)")
	egressFile      = flag.String("egress-file", "/data/proxy/egress.json", "the outbound-service allow-list (mode off, monitor or enforce; the page edits it)")
	actionsFile     = flag.String("actions-file", "/data/proxy/actions.json", "scheduled actions (snapshot, update lists, diagnostics, reboot)")
	eventsFile      = flag.String("events-file", "/data/proxy/events.json", "the newest events (new device, uplink down, ...)")
	notifyFile      = flag.String("notify-file", "/data/proxy/notify.json", "the optional ntfy address (0600; never shown back)")
	knownFile       = flag.String("known-devices", "/data/proxy/knowndevices.json", "MACs seen before, so only a really new device raises an event")
	canaryIP        = flag.String("canary", "192.168.1.253", "the canary (decoy) address on the LAN; empty switches the canary off entirely")
	arpWatchOn      = flag.Bool("arp-watch", true, "watch the bridge for ARP spoofing (gateway impersonation, address conflicts)")
	torFile         = flag.String("tor-file", "/data/proxy/tor.json", "Tor settings (daemon on/off, house-wide .onion, the devices sent through Tor)")
	torBin          = flag.String("tor-bin", "/data/proxy/tor", "the Tor client binary (recipe orbic-tor)")
	rogueFile       = flag.String("rogue-file", "/data/proxy/rogue.json", "DHCP servers the owner allowed (their MAC addresses)")
	torExitFile     = flag.String("tor-exit-file", "/data/proxy/tor-exits.txt", "known Tor relay/bridge addresses, one IP or CIDR per line; empty or missing turns tor_bypass_exit off")
	tlsSNIWatchOn   = flag.Bool("tls-sni-watch", true, "watch the bridge for TLS connections with no SNI or an IP-literal SNI (bare-IP TLS), and for a JA3 fingerprint match")
	lanAnnounceOn   = flag.Bool("lan-announce-watch", true, "watch the bridge for mDNS and SSDP announcements (LAN announcements): what devices say they are, and name conflicts)")
	lanAnnounceFile = flag.String("lan-announce-file", "/data/proxy/lanannounce.json", "where the LAN announcement watch keeps its inventory; empty keeps it in memory only")
	dnsXCheckOn     = flag.Bool("dns-xcheck", true, "sample encrypted DNS answers and ask the other configured DoH resolver the same question (resolver cross-check)")
	tlsCertWatchOn  = flag.Bool("tls-cert-watch", true, "watch the bridge for a server's certificate or TLS version changing in the way an interception looks (certificate change)")
	tlsCertFile     = flag.String("tls-cert-file", "/data/proxy/tlscert.json", "where the certificate-change watch keeps its per-name baseline; empty keeps it in memory only")
	ja3File         = flag.String("ja3-file", "/data/proxy/ja3-blocklist.txt", "known-malicious JA3 hashes, one '<md5 hash>,<name>' pair per line; empty or missing turns tls_ja3_match off")
	ttlWatchOn      = flag.Bool("ttl-watch", true, "watch the bridge for a device forwarding for others behind it, read from the IP TTL of each connection's first packet (hidden router)")
	ttlFile         = flag.String("ttl-file", "/data/proxy/ttlwatch.json", "devices marked expected by the hidden-router watch; empty keeps them in memory only")
	adminTripOn     = flag.Bool("admin-tripwire", true, "raise an event when something knocks on the switched-off stock admin's ports 81 and 444 (stock admin tripwire)")
	rebindFile      = flag.String("rebind-file", "/data/proxy/rebind.json", "DNS rebinding refusal settings (on/off, the names allowed to resolve to a private address)")
	dhcpFPWatchOn   = flag.Bool("dhcp-fp-watch", true, "watch the bridge for DHCP fingerprint drift (option 55 shape changing on a MAC that had settled)")
	rogueWatchOn    = flag.Bool("rogue-dhcp", true, "watch the bridge for DHCP replies from any server other than this Orbic")
	linkFile        = flag.String("link-file", "/data/proxy/linkhist.json", "uplink latency and loss history (hourly, about 35 days)")
	speedFile       = flag.String("speed-file", "/data/proxy/speed.json", "uplink speed test settings and history")
	canaryFile      = flag.String("canary-file", "/data/proxy/canary.json", "canary settings (on/off, ignored devices)")
	exportFile      = flag.String("export-file", "/data/proxy/export.json", "export settings: syslog target, packet tap on/off, Home Assistant broker (0600; may hold a broker password)")
	presenceFile    = flag.String("presence-file", "/data/proxy/presence.json", "when each device was last seen, what it calls itself, and which are watched")
	devNotesFile    = flag.String("dev-notes", "/data/proxy/devnotes.json", "labels and notes for devices (display only)")
	qcmapCfgFile    = flag.String("qcmap-cfg", "/usrdata/data/qcmap/mobileap_cfg.xml", "stock config holding the DHCP pool")
	uiTokenFlag     = flag.String("ui-token-file", "", "file holding the API-key token that scripts send as X-UI-Token instead of signing in (empty = script tokens are OFF and every such header is refused; the web login is unaffected)")
	vpnDir          = flag.String("vpn-dir", "/data/proxy/vpn", "directory for the Mullvad exit's state (holds this device's WireGuard key, mode 0600; empty = VPN off)")
	uiListen        = flag.String("ui-listen", ":3129", "address for the HTTPS web page (login required); empty = the web page is off")
	onionListen     = flag.String("onion-listen", "127.0.0.1:3130", "loopback address of the web page for the onion door (plain HTTP, read-only by default; Tor is its only client); empty = off")
	uiHost          = flag.String("ui-host", "orbic", "the name plain-HTTP requests are redirected to (https://<name>/...)")
	secureDir       = flag.String("secure-dir", "/data/proxy/secure", "directory (mode 0700) for the login hash and the HTTPS certificate")
	setLogin        = flag.String("set-login", "", "set the web login for this user (the password is read from stdin) and exit")
	setWifi         = flag.String("set-wifi", "", "set the Wi-Fi name (the password is the first line of stdin; an empty line keeps the current one) on both radios and exit")
	setWifi5        = flag.String("set-wifi-5ghz-name", "", "with -set-wifi: also rename the 5 GHz network (empty leaves its name alone; it must differ from the 2.4 GHz name)")
	wlanXMLFlag     = flag.String("wlan-xml", "/usrdata/data/usr/wlan/wlan_conf_6174.xml", "the stock Wi-Fi settings file the Wi-Fi page edits")
	sysDir          = flag.String("sys", "/sys", "sysfs root (a flag so tests can use a fixture)")
	procDir         = flag.String("proc", "/proc", "procfs root (a flag so tests can use a fixture)")
)

// builtinPAC is served when -pac is not given. Everything goes through the proxy
// except the local subnets and loopback.
func builtinPAC() string {
	return "function FindProxyForURL(url, host) {\n" +
		"  if (isPlainHostName(host)\n" +
		"      || shExpMatch(host, \"192.168.*\")\n" +
		"      || shExpMatch(host, \"10.*\")\n" +
		"      || shExpMatch(host, \"172.16.*\")\n" +
		"      || host == \"127.0.0.1\"\n" +
		"      || host == \"localhost\")\n" +
		"    return \"DIRECT\";\n" +
		"  return \"PROXY " + *proxyHost + "\";\n" +
		"}\n"
}

func servePAC(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if *pacFile != "" {
		b, err := os.ReadFile(*pacFile)
		if err != nil {
			http.Error(w, "pac unavailable", http.StatusInternalServerError)
			return
		}
		body = b
	} else {
		body = []byte(builtinPAC())
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}

func isPACPath(p string) bool {
	switch p {
	case "/wpad.dat", "/proxy.pac", "/wpad.da", "/", "/wpad", "/proxy":
		return true
	}
	return false
}

// dialUpstream connects to an upstream host, forcing IPv4 when -4 is set so we
// never stall on an AAAA record the cellular link cannot route.
func dialUpstream(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if *ipv4Only {
		switch network {
		case "tcp", "tcp6":
			network = "tcp4"
		case "udp", "udp6":
			network = "udp4"
		}
	}
	return d.DialContext(ctx, network, addr)
}

// hop-by-hop headers must not be forwarded (RFC 7230 6.1)
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// transport used for outbound HTTP forwarding. Proxy is explicitly nil so we
// never chain through an http_proxy that happens to be in our environment.
var transport = &http.Transport{
	Proxy:                 nil,
	DialContext:           proxyDialDirect,
	MaxIdleConns:          64,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func allowed(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	dst, err := vpn.DialFor(r.Context(), clientIP(r.RemoteAddr), "tcp", r.Host)
	if err != nil {
		log.Printf("CONNECT dial error for %s: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		dst.Close()
		return
	}
	src, _, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	src.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	connsTotal.Add(1)
	connsActive.Add(1)
	defer connsActive.Add(-1)
	client, host := clientIP(r.RemoteAddr), hostOnly(r.Host)
	upDone := make(chan uint64, 1)
	go func() { n := countedCopy(dst, src); dst.Close(); upDone <- n }()
	down := countedCopy(src, dst)
	src.Close()
	account(client, host, <-upDone, down, true)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "this is a forward proxy; use an absolute URI", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Close = false
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	tr, terr := vpn.TransportFor(clientIP(r.RemoteAddr))
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusBadGateway)
		return
	}
	resp, err := tr.RoundTrip(out)
	if err != nil {
		log.Printf("upstream error for %s %s: %v", r.Method, r.URL, err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	connsTotal.Add(1)
	connsActive.Add(1)
	defer connsActive.Add(-1)
	var up uint64
	if r.ContentLength > 0 {
		up = uint64(r.ContentLength)
	}
	account(clientIP(r.RemoteAddr), hostOnly(r.URL.Host), up, countedCopy(w, resp.Body), true)
}

func clientIP(remote string) string {
	h, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return h
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

var porchRelayOn *bool

func main() {
	porchRelayOn = flag.Bool("porch-relay", false, "relay the outside ports 80/443/8080/8443 to a service on the LAN (needs the stock admin moved to 81/444; off by default)")
	flag.Parse()
	log.SetOutput(os.Stderr)
	if *setLogin != "" {
		pw, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		a := NewAuth(filepath.Join(*secureDir, "auth.json"))
		if err := a.SetLogin(*setLogin, strings.TrimRight(string(pw), "\r\n")); err != nil {
			fmt.Fprintln(os.Stderr, "not set:", err)
			os.Exit(1)
		}
		fmt.Println("login set for", *setLogin)
		os.Exit(0)
	}
	if *setWifi != "" {
		msg, err := setWifiCLI(newWifiManager(defaultWifiEnv()), *setWifi, *setWifi5, os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "not set:", err)
			os.Exit(1)
		}
		fmt.Println(msg)
		os.Exit(0)
	}
	for _, c := range strings.Split(*allowFlag, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Fatalf("bad CIDR %q: %v", c, err)
		}
		allowNets = append(allowNets, n)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if *verbose {
			log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.Host)
		}
		if r.Method == http.MethodConnect {
			handleConnect(w, r)
			return
		}
		if !r.URL.IsAbs() && r.Method != http.MethodConnect {
			if !httpStays(r) { // the web page and its API live on HTTPS only
				redirectHTTPS(w, r)
				return
			}
			switch r.URL.Path {
			case "/status.json":
				serveStatus(w, r)
				return
			case "/metrics":
				serveMetrics(w, r)
				return
			case "/dhcp-hook":
				handleDHCPHook(w, r)
				return
			case "/beat":
				handleBeat(w, r)
				return
			}
			servePAC(w, r)
			return
		}
		handleHTTP(w, r)
	})

	srv := &http.Server{
		Addr:         *listenAddr,
		Handler:      h,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}
	loadState()
	debug.SetMemoryLimit(48 << 20)
	debug.SetGCPercent(40) // the live heap is small, so a tighter target costs little CPU and keeps resident memory near the live size (default 100 let it sit at twice that)
	if *dnsListen != "" {
		uiTokenFile = *uiTokenFlag
		flt := NewFilter(*dnsDir)
		flt.Load()
		debug.FreeOSMemory() // hand the lists' parse garbage back to the OS now, not whenever the scavenger gets to it
		up := newUpstream(upstreamConfig{DoHURLs: strings.Split(*dnsDoH, ","), Roots: rootPool(), Plain: carrierResolvers(*dnsResolv), PlainAfter: *dnsPlainAfter, Dial: dialUpstream})
		dnsProxy = &DNSProxy{Filter: flt, Up: up, Cache: newDNSCache(2000), Stats: NewDNSStats(), BlockTTL: 60, Neigh: newNeighbours()}
		dnsUpdater = newListUpdater(flt)
		if err := serveDNS(dnsProxy, *dnsListen); err != nil {
			log.Printf("dns filter disabled: %v", err)
			dnsProxy = nil
		} else {
			dnsUpdater.Schedule()
		}
	}
	if *porchRelayOn {
		startPorchRelay()
	}
	go usageLoop()
	linkMgr = newLinkHist(*linkFile)
	go probeLoop()
	go watchdogLoop()
	if *vpnDir != "" {
		vpn = NewVPN(*vpnDir, &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12}, DialContext: dialUpstream, TLSHandshakeTimeout: 20 * time.Second}})
		vpn.Load()
		if dnsProxy != nil {
			vpn.canon = dnsProxy.Neigh.canonical
			dnsProxy.VPN = vpn
		}
		go vpn.Run()
	}
	wifi = newWifiManager(defaultWifiEnv())
	dhcpMgr = defaultDHCPManager()
	poolMgr = defaultPoolManager(dhcpMgr)
	macMgr = defaultMacFilter()
	go macMgr.Run()
	fwMgr = defaultFWManager()
	go fwMgr.Run()
	devMgr = defaultDevNotes()
	go graphLoop()
	events = newEventStore()
	exports = newExportStore(*exportFile)
	events.sink = exportSink
	hass = newHassPublisher()
	go hass.run()
	go eventLoop()
	actions = defaultActionManager()
	go actions.Loop()
	presence = newPresenceStore()
	go presenceLoop()
	if ip := net.ParseIP(*canaryIP); ip != nil && ip.To4() != nil {
		canaryMgr = newCanary(ip)
		go canaryMgr.Run()
	}
	if *arpWatchOn {
		arpMgr = newARPWatch()
		arpMgr.Start()
	}
	if dnsProxy != nil && *dnsXCheckOn {
		dnsXMgr = newDNSXWatch(dnsProxy.Up)
	}
	if *lanAnnounceOn {
		lanAnnounceMgr = newLANAnnounceWatch(*lanAnnounceFile)
		lanAnnounceMgr.Start()
	}
	if dnsProxy != nil {
		dnsCanaryMgr = newDNSCanaryWatch()
		dgaMgr = newDGAWatch()
		dnsMITMMgr = newDNSMITMWatch()
		rebindMgr = newRebindGuard(*rebindFile)
	}
	macChurnMgr = newMACChurnWatch()
	torBypassMgr = newTorBypassWatch(*torExitFile)
	beaconMgr = newBeaconWatch("/data/proxy/beacon.json")
	if *tlsSNIWatchOn {
		tlsSNIMgr = newTLSSNIWatch(*ja3File)
		tlsSNIMgr.Start()
	}
	if *tlsCertWatchOn {
		tlsCertMgr = newTLSCertWatch(*tlsCertFile)
		tlsCertMgr.Start()
	}
	if *dhcpFPWatchOn {
		dhcpFPMgr = newDHCPFPWatch()
		dhcpFPMgr.Start()
	}
	if *ttlWatchOn {
		ttlMgr = newTTLWatch(*ttlFile)
		ttlMgr.Start()
	}
	if *rogueWatchOn {
		rogueMgr = newRogueWatch()
		rogueMgr.Start()
	}
	torMgrG = newTorMgr()
	if dnsProxy != nil {
		dnsProxy.Tor = torMgrG
	}
	go torMgrG.Run()
	go newOnionBridge(torMgrG.onions).Serve(torHouseIP + ":" + strconv.Itoa(torBridgePort))
	speedMgr = newSpeedTester(*speedFile)
	go speedMgr.Loop()
	snaps = defaultSnapStore()
	sshMgr = defaultSSHManager()
	stockMgr = defaultStockAdmin()
	stockAdminOff = stockMgr.Off
	go stockMgr.Run()
	if *adminTripOn {
		adminTripMgr = newAdminTrip()
		adminTripMgr.Start()
	}
	egressM = newEgressMgr(*egressFile)
	go egressM.Run()
	lanV6Mgr = defaultLanV6()
	go lanV6Mgr.Run()
	if *uiListen != "" {
		webAuth = NewAuth(filepath.Join(*secureDir, "auth.json"))
		webAuth.Load()
		uiTokenFile = *uiTokenFlag
		cm, created, err := newCertManager(filepath.Join(*secureDir, "tls"),
			[]string{"orbic", "orbic.lan", "wpad", "wpad.lan", "localhost"}, []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.254"), net.ParseIP("127.0.0.1")})
		if err != nil {
			log.Printf("web page off: certificate: %v", err)
		} else {
			certMgr = cm
			if created {
				log.Printf("made a new self-signed certificate")
			}
			log.Printf("web page certificate SHA-256: %s", cm.Fingerprint())
			go cm.Run()
			ui := &webUI{auth: webAuth, fpFn: cm.Fingerprint}
			hs := &http.Server{Addr: *uiListen, Handler: ui.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
				TLSConfig: &tls.Config{GetCertificate: cm.GetCertificate, MinVersion: tls.VersionTLS12}}
			go func() { log.Printf("web page: %v", hs.ListenAndServeTLS("", "")) }()
			if *onionListen != "" {
				if !isLoopbackAddr(*onionListen) {
					log.Printf("onion web page off: %q is not a loopback address", *onionListen)
				} else {
					ohs := &http.Server{Addr: *onionListen, Handler: ui.onionHandler(func() bool { return torMgrG.RemoteWrite() }), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
					go func() { log.Printf("onion web page: %v", ohs.ListenAndServe()) }()
				}
			}
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; saveState(); os.Exit(0) }()
	log.Printf("tinyfwd %s listening on %s, allow=%s", version, *listenAddr, *allowFlag)
	log.Fatal(srv.ListenAndServe())
}
