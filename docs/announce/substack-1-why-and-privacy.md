# Stone of Heimdall

Stone of Heimdall is firmware for the Orbic RC400L, a small cellular hotspot. It replaces the hotspot's admin page with one of its own and changes what the hotspot lets your devices do.

The reason it exists: a hotspot answers every name lookup your devices make and forwards every connection they open, and it does both without a filter and without a record. The carrier's resolver sees the names in plain text. Trackers are reached by name and nothing refuses them. Devices open connections to wherever they like, on whatever port they like.

What the firmware changes:

Name lookups leave encrypted, over DNS-over-HTTPS, or inside the VPN, or through Tor. Plain DNS and DNS-over-TLS are refused on the cellular side.

A DNS filter: published block lists you tick, rules you write, applied to everyone or to one device.

An outbound allow-list. In enforce mode a device may only open connections on the ticked services and ports. Web, QUIC, clock sync, ssh, email and push notifications are ticked by default; calls, consoles, VPN protocols, torrents, remote desktop, MQTT and IRC are not. There is a monitor mode first: the box tallies, per device, which ports would have been refused, so the list can be built from what the house actually uses before anything breaks.

Per-device exits: direct, a Mullvad WireGuard tunnel with a kill switch, or Tor.

LAN IPv6 off by default. A device behind the tunnel still holds its carrier IPv6 address, the tunnel carries only IPv4, and a browser will give that address to any page that asks for it through WebRTC. The only cure at the router is for the device not to have one.

The carrier's firmware-update and device-management engines kept suspended.

What it is not: anonymity. The carrier knows where the hotspot is and sees that you connected, when, and how much. A VPN provider sees what the carrier otherwise would. It cannot see inside encrypted traffic and does not try. It has run on one unit, of one model, on one carrier.

## The page

One page, served over HTTPS from the hotspot, behind a login. Cards in sections: Today, Monitoring, Security, Privacy, DNS, Devices, Network, System. Every card collapses. No telemetry. Nothing leaves the house unless you configure it to.

**Today.** Counts since the box started: queries, blocked, cached, encrypted, plain, via VPN, errors. The filter on or off. Pause it for fifteen minutes, resume, update the lists now. A banner when encrypted DNS is down and plain carrier DNS is being used instead.

**Tor.** A minimal client-only Tor runs on the box, supervised by the firmware. Any device can open a .onion address with no setup: the DNS stub answers the name with an address from a reserved range and a firewall rule sends that traffic through Tor. A device can also be assigned to exit through Tor entirely. While Tor is down an assigned device gets no answer, never a public one. The card shows bootstrap state, memory use and assignments.

**Onion door.** A Tor onion service that lets a few keyed devices reach this page from anywhere, with no open port. Three locks: v3 client authorisation, so a visitor without a listed key cannot find the service at all; the web login; and a read-only view unless remote writing is on. No SSH through it.

**VPN (Mullvad).** One WireGuard key, run in-process. The whole house can exit through it, with a kill switch so a dead tunnel blocks instead of leaking, or single devices by MAC address. Registration takes a Mullvad account number, used once and not stored. The card shows the tunnel state, the relay chosen by country and city, and each device's exit.

**Block lists.** A catalogue of published lists, each a tick box. Lists are held in memory as hashes, so switching one on or off is instant, with no reload and no DNS stall. A per-device "strict" profile applies every list downloaded.

**Always allow.** Names that resolve whatever the lists say. Allow wins. That is how you unbreak a site without dropping a whole list.

**Your block rules.** A bare name blocks it and its subdomains. A star prefix blocks subdomains only. Stars anywhere match anything. A rule applies to everyone or to one device, and can expire after an hour, a day or a week. Below it, a "Why?" box: type a name and it says which list or rule blocks it, or that nothing does.

**Top blocked. Top asked. Recent.** Counted since the box started: the names blocked most, the names asked most, and the newest queries, each with the device that asked and how it was answered. These live in RAM only. There is no query history on flash.
