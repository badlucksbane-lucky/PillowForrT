# What it watches

Stone of Heimdall, firmware for the Orbic RC400L hotspot. The cards that observe: wire, radio, uplink, devices. They record. You act.

## Monitoring

**Events.** A detector runs every 20 s. Records: new device, uplink down and back, DoH failing, a service dead, box hot, burst of failed ssh logins, radio dropped, certificate renewed, data plan threshold crossed, restart. Newest 100 kept. Optional push to an ntfy topic above a chosen severity. Off until you give a URL. The pushed text is a generic sentence: no name, MAC, address or key.

**Latency history.** Live graphs hold a day in RAM. This holds weeks on flash in hourly buckets: probes run, probes failed, mean and worst connect time. Probe is a TCP connect to 1.1.1.1:443 every 30 s. Three failures in a row is an outage, logged from first failure to first success. Lossy but not down raises `uplink_flaky`.

**Speed history.** Every 6 h by default: 1 MB down, 256 KB up, Cloudflare speed endpoints. About 5 MB a day. Kept on flash, charted. Same size every run, so the trend is the point, not the peak.

## Security

**ARP watch.** Passive AF_PACKET socket on the bridge, kernel filter passes ARP only. Looks at who claims an address. `arp_gateway` (alert): a foreign MAC claims the router's address. `arp_conflict` (alert): a MAC claims an address reserved for another device. `arp_flip` (to look at): an address changes owner within 10 minutes. Poisoning looks like that; so does a device rejoining under a random MAC. One event per address per 10 minutes. Limit: unicast ARP between two Wi-Fi clients is relayed inside the radio and never reaches the bridge.

**Rogue DHCP.** AF_PACKET socket, filter passes UDP from port 67 only. Every offer, ack and nak is checked. Honest only if it comes from the box's own address and the bridge's own MAC. Anything else is flagged.

**Canary.** 192.168.1.253, an alias on the LAN bridge. No honest device has a reason to touch it. TCP listeners on tempting ports (tarpit, never a service). Any packet or ARP who-has aimed at it is recorded: time, source, MAC, protocol, port, kind (syn, connect, udp, echo, who-has).

## Devices

**Devices.** One row per device, joined from: radio (band, time connected), ARP and NDP (IPv4, global IPv6), reservations and leases (names), block list, pauses and schedules, DNS activity, VPN exit. Wired or asleep still shows from reservation or lease. Label and note per device. Wake-on-LAN.

**Wi-Fi.** SSID, password, hidden, channel, max clients, client isolation, country, bandwidth. 5 GHz band has its own SSID, hidden, channel, enabled. Password is write-only: never returned, logged or shown. Each change: backup, edit the firmware's XML, restart `wland`, verify the regenerated hostapd config, roll back on mismatch. Devices rejoin in about 20 s.

**Blocked devices.** By MAC. The stock deny list does not hold on this driver (a dropped device walked straight back in). Enforced in the firewall instead.

**Internet schedules.** Weekly windows and pause-until-time, per device. Cuts internet. LAN, DHCP and this page stay.

## Network

**DHCP reservations.** MAC to fixed IP and name. One line per device in dnsmasq's hostsfile. SIGHUP to reload. Validated, backed up, written atomically.

**DHCP pool.** First, last, lease time. Edits the firmware's own XML so a reboot keeps it, relaunches dnsmasq now with the new range.

**Blocked destinations.** IP or CIDR no device may reach. Applies to the box too, so proxied traffic is covered. For trackers reached by hard-coded address, which DNS rules cannot catch.
