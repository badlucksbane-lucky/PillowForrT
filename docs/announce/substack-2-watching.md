# Stone of Heimdall, part 2 of 3: the half that watches

Part 1 said why Stone of Heimdall exists and walked through the privacy cards on its web page: encrypted DNS, the filter, the VPN and Tor exits. This part covers the cards that watch the network. The principle is the same one from part 1: the hotspot reports what it sees, and you decide.

## Monitoring

### Events

A detector looks at the box every twenty seconds and records what deserves attention: a device it has never seen before, the uplink going down and coming back, encrypted DNS failing, a service dying, the box running hot, bursts of failed SSH logins, a radio dropping out, the web certificate being renewed, the data plan crossing a threshold, and restarts. The newest hundred are kept and shown here. Optionally, events above a chosen severity are pushed to a notification endpoint you choose.

### Latency history

The live graphs keep a day in memory. This card keeps weeks on flash, in hourly buckets: how many uplink probes ran, how many failed, and the average and worst connect time. It also keeps an outage log, so "was last Tuesday evening bad?" has an answer. A link that is lossy without being down raises its own event.

### Speed history

Every few hours the hotspot times a small download and upload over the cellular link and charts the result. The test is deliberately small, about five megabytes a day at the default interval, because the point is the trend: is the evening slower, did the carrier throttle, did moving the antenna help.

## Security

### ARP watch

ARP has no authentication, so any device on the network can claim to be the gateway and pull everyone's traffic through itself. The hotspot watches every ARP frame on the bridge passively and looks at who claims which address. A foreign MAC claiming the router's address is an alert. Two devices claiming the same address, or one device changing its MAC, are findings of their own.

### Rogue DHCP

A second DHCP server on the network, whether a plugged-in router, a phone sharing its connection, or a hostile device, can hand out its own gateway and DNS and steer every device that listens. The hotspot is the only legitimate server, so it watches every DHCP reply on the wire and flags any that did not come from itself.

### Canary

A decoy address that no honest device has any reason to touch. The hotspot answers for it, listens on a set of tempting ports there (a slow tarpit, never a real service), and watches for any packet aimed at it, including pings and ports nothing listens on. Anything that touches the canary is looking around: a port scanner, a worm, a compromised device, a curious guest. The card lists who touched it and when.

## Devices

### Devices

Every device the hotspot knows about, one row each, joined from the separate sources: the radio (which band, how long connected), the ARP and neighbour tables (addresses, IPv4 and IPv6), the DHCP reservations and leases (names), the block list, the schedules, DNS activity and the VPN exit. A device the radio does not list, because it is wired or asleep, still shows from its reservation or lease. You can give a device a label and a note, and send wake-on-LAN.

### Wi-Fi

The network names and passwords for both bands, moved here from the stock admin. Every change is backed up first and verified against the configuration the firmware regenerates. Devices rejoin within about twenty seconds.

### Blocked devices

Devices, by MAC address, that are cut off from the network. The stock firmware's own deny list turned out not to hold on this driver (a dropped device walked straight back in), so the block is enforced where it does hold, in the firewall.

### Internet schedules

A device's internet is cut during a weekly window, or paused until a time, while its LAN access, DHCP and this page stay reachable. The pauses are the quick "fifteen more minutes" kind; the schedules are the weekly kind.

## Network

### DHCP reservations

Fixed addresses and names for chosen devices.

### DHCP pool

The first address, last address and lease time, moved here from the stock admin. Changing the pool edits the firmware's own configuration file so a reboot keeps it, and relaunches the DHCP server now.

### Blocked destinations

An address or range no device on the network may reach, the hotspot itself included, so proxied traffic is covered too. This is the blunt instrument for a hard-coded tracker address that no DNS rule can catch.

Part 3 covers the system cards, how the software was made, and what you should know before you install it.
