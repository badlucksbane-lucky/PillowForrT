# Stone of Heimdall

Firmware for the Orbic RC400L, a cheap cellular hotspot. It swaps out the stock admin page and changes what the box lets your devices do.

The short version of why: the stock firmware forwards your DNS in plain text to the carrier, resolves tracker domains like anything else, and lets every device open whatever connection it wants on whatever port. No filter, no log, no switch. So this adds the filter, the log and the switch.

What it does:

- All DNS leaves as DoH (Quad9, Cloudflare), or inside the VPN, or through Tor. Port 53 and DoT are refused on the cellular side, so nothing sneaks around it.
- DNS filter. Published block lists, your own wildcard rules, per device if you want.
- Default-deny outbound. Devices only get the services you tick. Web, QUIC, NTP, ssh, email and push are ticked out of the box. Calls, consoles, VPN protocols, torrents, remote desktop, MQTT and IRC aren't.
- Per-device exit: direct, Mullvad WireGuard with a kill switch, or Tor.
- LAN IPv6 off by default. More on that below.
- The carrier's firmware-update and remote-management daemons are kept asleep.

## The bits worth knowing about

**It watches before it blocks.** Default-deny on day one would break everything, because you don't know yet what your devices need. So there's a monitor mode: it reads the conntrack table every 10 seconds and tallies, per device, what *would* have been refused. You look at the list, tick what you recognise, then flip it to enforce.

**The IPv6 leak.** Put a device behind a WireGuard tunnel and you'd think it's covered. The tunnel is IPv4-only. The device still has its real carrier IPv6 address, and WebRTC will hand that address to any web page that asks. The only fix at the router is for the device to never get one, so the LAN hands out no IPv6 unless you turn it on.

**.onion for the whole house.** A small client-only Tor runs on the box. Any device can open a .onion name with zero setup: the DNS stub answers a v3 .onion with an address from 198.18.0.0/16 and a firewall rule sends that TCP through a bridge to Tor's SOCKS port. Had to be 198.18/16 because dnsmasq's rebind protection silently eats answers in private ranges. You can also assign a device to exit through Tor entirely. If Tor's down, that device gets SERVFAIL, never a public resolver.

**The canary.** 192.168.1.253 is a decoy. No honest device has any reason to talk to it. The box answers for it, listens on a few tempting ports as a tarpit, and logs anything that so much as pings it or ARPs for it. Anything on the list is looking around: a scanner, a worm, something compromised, a nosy guest.

**ARP watch.** Passive socket on the bridge, ARP frames only. A foreign MAC claiming the router's address is an alert. A MAC claiming an address reserved for a different device is an alert. An address changing hands within 10 minutes is flagged to look at, because poisoning looks like that, but so does a phone rejoining with a fresh random MAC. Honest limit: ARP between two Wi-Fi clients gets relayed inside the radio and never reaches the bridge.

**Blocked devices, the hard way.** The stock firmware's Wi-Fi deny list doesn't actually hold on this driver. A dropped device walked straight back in. So the block goes in the firewall, where it sticks.

**"Why?"** A box under your block rules. Type a domain, it tells you which list or rule blocks it, or that nothing does. Saves a lot of guessing.

**Onion door.** An onion service that gets you to this page from anywhere, no open port. Three locks: v3 client authorisation (no listed key, the service isn't even findable), the normal login, and read-only unless you turn remote write on. No SSH through it.

## The rest of the page

One page over HTTPS behind a login, cards that collapse, no telemetry. Also on it:

- Events: new device, uplink down and back, DoH failing, box hot, failed ssh bursts, cert renewed, plan threshold, restarts. Optional push to an ntfy topic, generic text only.
- Latency and speed history on flash, weeks of it, hourly buckets. "Was Tuesday evening bad?" has an answer.
- Rogue DHCP detection: any offer or ack not from the box's own MAC gets flagged.
- Devices table joined from radio, ARP, NDP, leases, reservations, schedules, DNS and VPN. Labels, notes, wake-on-LAN.
- Wi-Fi settings, both bands. Password is write-only. Every change backed up and verified, rolls back on mismatch.
- Internet schedules and pauses per device. LAN and this page stay reachable.
- DHCP reservations and pool, blocked destinations by IP or CIDR.
- Diagnostics: one click, every check, plain-words verdict, shareable report with nothing identifying in it.
- System, cellular (read-only), certificate renewal, key-only SSH with an audit trail, scheduled actions from a fixed list, settings snapshots restorable per section, a read-only SMS inbox, one login with bcrypt.

## Before you trust it

Written by Claude, Anthropic's model, under my direction. I set the goals and made the calls and tested it on my own box. I didn't write the code and haven't audited it line by line. There's a big test suite and one unit's worth of real use. Read it before you trust it with anything that matters.

One unit, one model, one carrier. The first-install tool hasn't been run end to end from a factory-fresh box yet. Rooting it may void the warranty or breach your carrier's terms. Reading some flash partitions freezes the thing until a power cycle.

Not anonymity. The carrier still knows where you are and when you're online. Mullvad sees what the carrier otherwise would. Doesn't cover physical access, someone on your Wi-Fi guessing the password, a device with its own radio, or holes in the old stock firmware underneath.

https://github.com/badlucksbane-lucky/stone-of-heimdall

MIT. "Orbic" is their trademark, named only to say what hardware this runs on. Not affiliated with Orbic or any carrier.
