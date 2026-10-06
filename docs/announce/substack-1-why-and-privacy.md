# A watchman for your hotspot

Every device you own asks a question before it does anything on the internet: where is this name? The phone asks it constantly. The television asks it while it is off. The bulb asks it at three in the morning. The question goes to whatever box is giving you Wi-Fi, and that box passes it on, in plain text, to the company that sells you the connection. Nobody shows you the questions. Nobody asks whether you wanted them asked.

Stone of Heimdall is firmware for one small cellular hotspot, the Orbic RC400L. The first thing it does is show you the questions.

A fresh install changes nothing. It listens. It writes down every name each device asked for and every address each device tried to reach, and it shows you the list, by device. Most of the list is what you expected. Some of it is not: a name you have never heard of, asked a thousand times by a device you thought was idle. Then you decide. You tick what you recognise, and only then does the box start refusing the rest. It watches before it guards.

What it refuses, once you tell it to:

The carrier's view of your names. Every lookup leaves encrypted, or inside a VPN, or through Tor. The plain kind is refused on the cellular side, so no device can quietly go around the filter.

The names on the lists. Ad networks, trackers, malware domains, from published lists you tick and rules you write yourself, for everyone or for one device.

Everything else. A device may open a connection to the web, to a clock server, to a mail server, to the push service that wakes its apps. It may not open a connection to anything else until you say so. Calls, game consoles, torrents, remote desktop and the rest are off until ticked.

There is one more leak, and it only shows up after you fix the others. Route a device through a VPN and the tunnel carries one kind of address, IPv4. The device still holds its other address, the real one from the carrier, in IPv6, and any web page can ask the browser for it and get it. The only cure at the router is for the device not to have one. So the LAN gives out no IPv6 unless you turn it on.

Each device gets its own exit: direct, a Mullvad WireGuard tunnel with a kill switch, or Tor. The carrier's own update and remote-management engines are kept asleep.

It is not anonymity. The carrier knows where the hotspot is and sees that you connected, when, and how much. A VPN provider sees what the carrier otherwise would. It cannot see inside encrypted traffic and does not try. It has run on one unit, of one model, on one carrier.

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
