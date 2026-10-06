# What it watches

Stone of Heimdall, firmware for the Orbic RC400L hotspot. The cards that observe: wire, radio, uplink, devices. They record. You act.

## Monitoring

**Events.** A detector looks at the box every twenty seconds and records what deserves attention: a device never seen before, the uplink dropping and coming back, encrypted DNS failing, a service dying, the box running hot, a burst of failed ssh logins, a radio dropping out, the certificate being renewed, the data plan crossing a threshold, a restart. The newest hundred are kept. Events above a chosen severity can be pushed to an ntfy topic you give it. That is the one outward-facing thing on the page, so it is off until you give a URL, and what is sent is a generic sentence, never a name, address or key.

**Latency history.** The live graphs keep a day in memory. This keeps weeks on flash, in hourly buckets: probes run, probes failed, average and worst connect time, and an outage log. "Was last Tuesday evening bad?" has an answer. A link that is lossy without being down raises its own event.

**Speed history.** Every few hours the box times a small download and upload over the cellular link and charts it. About five megabytes a day at the default. The point is the trend: is the evening slower, did the carrier throttle, did moving the antenna help.

## Security

**ARP watch.** ARP has no authentication. Any device can claim to be the gateway and pull everyone's traffic through itself. The box watches every ARP frame on the bridge, passively, and looks at who claims which address. A foreign MAC claiming the router's address is an alert. So is a MAC claiming an address reserved for a different device. An address that changes owner within ten minutes is marked to look at, since poisoning looks like that, but so does a device rejoining under a new random MAC. The box sees broadcasts and what is aimed at itself; ARP between two Wi-Fi clients is relayed inside the radio and never reaches it.

**Rogue DHCP.** A second DHCP server on the network, from a plugged-in router, a phone sharing its connection, or something hostile, can hand out its own gateway and DNS and steer every device that listens. The box is the only legitimate server. It watches every DHCP reply on the wire and flags any that did not come from itself.

**Canary.** A decoy address no honest device has a reason to touch. The box answers for it, listens on tempting ports there (a slow tarpit, never a real service), and watches for any packet aimed at it, pings and dead ports included. Whatever touches the canary is looking around: a scanner, a worm, a compromised device, a curious guest. The card lists who, and when.

## Devices

**Devices.** Every device the box knows, one row each, joined from the separate sources: the radio (band, time connected), the ARP and neighbour tables (IPv4 and IPv6 addresses), reservations and leases (names), the block list, schedules, DNS activity, the VPN exit. A wired or sleeping device still shows from its reservation or lease. A device can carry a label and a note, and be woken over the LAN.

**Wi-Fi.** Network name, password, channel, client isolation and the 5 GHz band's own settings, taken over from the stock admin. The password is write-only: never returned, logged or shown. Every change is backed up first and checked against the configuration the firmware regenerates. Devices rejoin in about twenty seconds.

**Blocked devices.** Devices, by MAC, cut off from the network. The stock firmware's own deny list does not hold on this driver: a dropped device walked straight back in. So the block is enforced where it does hold, in the firewall.

**Internet schedules.** A device's internet is cut during a weekly window, or paused until a time. Its LAN access, DHCP and this page stay.

## Network

**DHCP reservations.** Fixed addresses and names for chosen devices.

**DHCP pool.** First address, last address, lease time. A change edits the firmware's own configuration file, so a reboot keeps it, and relaunches the DHCP server now.

**Blocked destinations.** An address or range no device may reach, the box itself included, so proxied traffic is covered too. The blunt instrument for a tracker reached by hard-coded address, which no DNS rule can catch.
