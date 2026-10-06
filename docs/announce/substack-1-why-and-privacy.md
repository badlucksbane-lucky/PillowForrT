# A watchman for your hotspot

A cellular hotspot is a router you never configured. It hands out addresses, answers every DNS question your devices ask, and forwards the rest to the carrier. The carrier's resolver sees every name you look up, in plain text. Ad and tracker networks are reached by name and nothing refuses them. Apps and gadgets phone home on any port, to any address, and you only find out if you go looking.

Put a device behind a VPN and a fourth problem appears. The tunnel carries IPv4. The device still holds its real carrier IPv6 address, and its browser will hand that address to any page that asks through WebRTC.

Stone of Heimdall is firmware for the Orbic RC400L that fixes these at the router, where every device's traffic passes anyway.

All DNS leaves encrypted, over DNS-over-HTTPS, inside the VPN, or through Tor. Plain DNS and DNS-over-TLS are refused on the cellular side. A filter blocks names from published lists and your own rules, per device if you like. Outbound connections are denied by default: a fresh install passes web, QUIC, clock sync, ssh, email and push notifications, and nothing else until you tick it. Each device gets its own exit: direct, Mullvad WireGuard with a kill switch, or Tor. LAN IPv6 is off, so a device has no carrier address to leak. The carrier's firmware-update and device-management engines are kept suspended.

It watches before it guards. Default-deny would be unusable on day one, because you do not yet know what your devices need. So a fresh install only records what each device tried to reach and shows it as a "would be refused" list. You tick what you recognise. Then you switch enforcement on.

It is not anonymity. The carrier knows where the hotspot is and sees connection metadata. The VPN provider sees what the carrier otherwise would. It cannot see inside encrypted traffic and does not try. It has run on one unit, of one model, on one carrier.

## The page

One page, served over HTTPS from the hotspot, behind a login. Cards in sections: Today, Monitoring, Security, Privacy, DNS, Devices, Network, System. Every card collapses. No telemetry. Nothing leaves the house unless you configure it to.

**Today.** Query count, how many were blocked, the share that left encrypted. Pause filtering for fifteen minutes, resume, update the lists now.

**Tor.** A minimal client-only Tor runs on the box, supervised by the firmware. Any device can open a .onion address with no setup: the DNS stub answers the name with an address from a reserved range and a firewall rule sends that traffic through Tor. A device can also be assigned to exit through Tor entirely. While Tor is down an assigned device gets no answer, never a public one. The card shows bootstrap state, memory use and assignments.

**Onion door.** A Tor onion service that lets a few keyed devices reach this page from anywhere, with no open port. Three locks: v3 client authorisation, so a visitor without a listed key cannot find the service at all; the web login; and a read-only view unless remote writing is on. No SSH through it.

**VPN (Mullvad).** One WireGuard key, run in-process. The whole house can exit through it, with a kill switch so a dead tunnel blocks instead of leaking, or single devices by MAC address. Registration takes a Mullvad account number, used once and not stored. The card shows tunnel state, exit server and assignments.

**Block lists.** A catalogue of published lists, each a tick box. Lists are held in memory as hashes, so switching one on or off is instant, with no reload and no DNS stall. A per-device "strict" profile applies every list downloaded.

**Always allow.** Names that resolve whatever the lists say. Allow wins. That is how you unbreak a site without dropping a whole list.

**Your block rules.** A bare name blocks it and its subdomains. A star prefix blocks subdomains only. Stars anywhere match anything. A rule applies to everyone or to one device, and can expire after an hour, a day or a week. Below it, a "Why?" box: type a name and it says which list or rule blocks it, or that nothing does.

**Top blocked. Top asked. Recent.** The last day: names blocked most, names asked most, the newest queries, each with the device that asked. These live in RAM only. There is no query history on flash.
