# Stone of Heimdall

Firmware for the Orbic RC400L cellular hotspot. Replaces the stock admin page. Changes what the hotspot lets your devices do.

Why: the stock firmware forwards DNS in plain text to the carrier's resolver, resolves tracker domains like any other, and forwards any outbound connection on any port. No filter, no log, no switch.

What it does:

- All DNS leaves as DoH (Quad9, Cloudflare), or inside the VPN, or through Tor. Port 53 and DoT (853) are refused on the cellular side.
- DNS filter: published block lists, your own wildcard rules, per device.
- Default-deny outbound. Enforce mode: a device opens connections only on the ticked services and ports. Default ticks: web, QUIC, NTP, ssh, email, push. Off: calls, consoles, VPN protocols, torrents, remote desktop, MQTT, IRC. Monitor mode first: tallies refused ports per device from the conntrack table so you build the allow-list from real use.
- Per-device exit: direct, Mullvad WireGuard with kill switch, or Tor.
- LAN IPv6 off by default. The tunnel is IPv4-only; a device keeps its carrier IPv6 address and WebRTC hands it to any page that asks. No address, no leak.
- Carrier firmware-update and device-management daemons kept suspended.

Not anonymity. The carrier sees location, connection times and volume. Mullvad sees what the carrier otherwise would. Encrypted payloads are not inspected. One unit, one model, one carrier tested.

## The page

One page over HTTPS, behind a login. Sections: Today, Monitoring, Security, Privacy, DNS, Devices, Network, System. Cards collapse. No telemetry.

**Today.** Counts since the box started: queries, blocked, cached, encrypted, plain, via VPN, errors. The filter on or off. Pause it for fifteen minutes, resume, update the lists now. A banner when encrypted DNS is down and plain carrier DNS is being used instead.

**Tor.** Client-only Tor on the box, supervised. Any device opens .onion names with no setup: the DNS stub answers a v3 .onion with an address from 198.18.0.0/16 and a firewall rule sends that TCP through the onion bridge to Tor's SOCKS port. A device can be assigned to exit through Tor entirely. Tor down: the assigned device gets SERVFAIL, never a public resolver. Card: bootstrap, RSS, restarts, assigned devices.

**Onion door.** An onion service for reaching this page from anywhere with no open port. Three locks: v3 client authorisation (no listed key, no service found), the web login, read-only unless remote write is on. No SSH through it.

**VPN (Mullvad).** One WireGuard key, one device slot, wireguard-go in-process. Whole house or single devices by MAC. Kill switch: tunnel down means blocked, not leaked. Account number used to register, not stored. Card: tunnel state, relay by country and city, per-device exit.

**Block lists.** Published lists, tick to use. Held in RAM as 64-bit hashes: toggling is instant, no reload, no DNS stall. Per-device "strict" applies every downloaded list.

**Always allow.** Names that resolve regardless. Allow wins over every list and rule.

**Your block rules.** `example.com` blocks it and subdomains. `*.example.com` subdomains only. `*track*` matches anything. Per device or everyone. Expiry: always, 1 hour, 1 day, 1 week. "Why?" box: type a name, get the list or rule that blocks it.

**Top blocked. Top asked. Recent.** Counters since start. Recent is a ring buffer: name, client, type, result (blocked, cached, doh, plain, error), latency. RAM only. No query history on flash.
