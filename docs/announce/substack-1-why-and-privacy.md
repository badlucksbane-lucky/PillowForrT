# Stone of Heimdall, part 1 of 3: why it exists, and the half that keeps traffic private

Stone of Heimdall is free, open-source firmware for the Orbic RC400L cellular hotspot. It replaces the hotspot's stock admin page with a single web page of collapsible cards, and underneath that page it changes what the hotspot lets your devices do.

This is the first of three posts. This one says why the software exists and walks through the cards that handle privacy. The second covers the cards that watch the network. The third covers housekeeping, and the caveats you should read before trusting it.

## Why it exists

A cellular hotspot is a router you never configured. It hands out addresses, answers every DNS question your devices ask, and forwards everything else to the carrier. Three parties get a clear view of what your devices do:

- **The carrier's resolver** sees every name you look up, in plain text, because the stock firmware sends DNS unencrypted.
- **Ad and tracker networks** are reached by name, and nothing on the hotspot refuses them.
- **Apps and gadgets that phone home** do so on any port they like, to any address, and you only find out if you go looking.

There is a fourth problem that only shows up once you try to fix the first three. If you put a device behind a VPN, its browser can still leak the device's real carrier IPv6 address through WebRTC, because the tunnel carries IPv4 and the address is still sitting on the device.

Stone of Heimdall deals with each of these at the router, where every device's traffic passes anyway:

- All DNS leaves encrypted, over DNS-over-HTTPS, or inside the VPN, or through Tor. Plain DNS and DNS-over-TLS are refused on the cellular side.
- A DNS filter with a catalogue of published block lists, your own wildcard rules, and per-device profiles.
- **Default-deny outbound.** A fresh install blocks every outbound connection except the services you tick (web, QUIC, clock sync, ssh, email and push notifications are on; calls, consoles, VPN protocols, torrents, remote desktop, MQTT and IRC are off) and the ports you add, globally or per device.
- Per-device exits: direct, Mullvad WireGuard with a kill switch, or Tor. LAN IPv6 is off by default so a device has no carrier IPv6 address to leak.
- The carrier's firmware-update and device-management engines are kept suspended.

## It watches before it guards

The default-deny rule would be unusable if it started enforcing on day one, because you do not yet know what your devices need. So a fresh install runs in watch-only mode: it records what each device tried to reach and shows it as a "would be refused" list. You read the list, tick what you recognise, and only then switch enforcement on. The same idea runs through the whole project. The page tells you what it sees first and asks you to decide.

## What it is not

It is not anonymity. The carrier still knows where the hotspot is and sees connection metadata. A VPN provider sees what the carrier otherwise would. It cannot see inside encrypted traffic and does not try to. It has been tested on one unit of one model on one carrier. Part 3 has the full list of limits.

## The page

Everything is one page served over HTTPS from the hotspot itself, behind a login. The cards sit in sections: Today, Monitoring, Security, Privacy, DNS, Devices, Network and System. Each card collapses, and the page remembers which ones you closed. No telemetry; nothing leaves the house unless you configure it to.

Here are the cards in the first half.

### Today

The hero card at the top. Today's query count, how many were blocked, and the share that left encrypted. Three buttons: pause filtering for fifteen minutes, resume, and update the block lists now.

## Privacy

### Tor

A minimal client-only Tor runs on the hotspot, supervised by the firmware, and it does two jobs. Any device on the network can open a .onion address with no setup: the DNS stub answers the name with an address from a reserved range and a firewall rule sends that traffic through Tor. Separately, you can assign a device to exit through Tor entirely. While Tor is down, an assigned device gets no answer rather than a public one. The card shows Tor's bootstrap state, memory use, and which devices are assigned.

### Onion door

A Tor onion service that lets a few keyed devices reach this page from anywhere, with no open port on the hotspot. Three locks: Tor v3 client authorisation, so a visitor without a listed key cannot even find the service; the normal web login; and a read-only view unless you turn remote writing on. There is no SSH through it.

### VPN (Mullvad)

One WireGuard key, run as an in-process tunnel. The whole house can exit through it, with a kill switch so a dead tunnel blocks instead of leaking, or single devices can, chosen by MAC address. You register with a Mullvad account number, which is used once and not stored. The card shows the tunnel state, the exit server, and the per-device assignments.

## DNS

### Block lists

A catalogue of published lists, each one a tick box. Lists stay in memory as hashes, so switching one on or off is instant with no reload and no DNS stall. A per-device "strict" profile applies every downloaded list.

### Always allow

Names that must resolve whatever the lists say. The allow list wins over everything else, which is how you unbreak a site without disabling a whole list.

### Your block rules

Your own patterns: a bare name blocks it and its subdomains, a star prefix blocks subdomains only, and stars anywhere match anything. A rule can apply to everyone or one device, and can expire after an hour, a day or a week. Underneath is a "Why?" box: type a name and it tells you which list or rule blocks it, or that nothing does.

### Top blocked, Top asked, Recent

Three live tables from the last day: the names blocked most often, the names asked most often, and the most recent queries, each attributed to the device that asked. These counts live in RAM only. There is no query history on flash.

Part 2 covers the other half of the page: the cards that watch the network for things that should not be there.
