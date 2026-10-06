# Threat model

DRAFT for the maintainer's review. What Stone of Heimdall is meant to defend against, what it is not, and where its claims stop.

## Who it is for
A person who carries a cellular hotspot and wants fewer third parties able to profile their devices' traffic: ad and tracker networks, the carrier's DNS resolver, apps that phone home, and devices on the same network that should not be talking to the internet at all.

## What it defends against
| Threat | What Stone of Heimdall does | Where the claim stops |
|---|---|---|
| The carrier's resolver logging every name you look up | All DNS leaves encrypted (DoH) or through the VPN or Tor; plain DNS (53) and DNS-over-TLS (853) are refused out of the cellular side | The carrier still sees the IP addresses you connect to, and the size and timing of the traffic |
| Ad, tracker and malware domains | DNS filter with published block lists, your own wildcard rules, per-device profiles, and a "why was this blocked?" check | A filter is not a guarantee: a tracker on an unlisted name, or one reached by a hard-coded IP, gets through |
| A device talking to places you never approved | Default-deny outbound: only ticked services and ports leave; a watch-only mode shows what would be refused before you enforce | Anything on an allowed port (web, QUIC) can still carry anything. This limits kinds of traffic, not content |
| Address leaks around a VPN | Per-device exits (direct, Mullvad WireGuard with a kill switch, or Tor); LAN IPv6 is off by default so a device's carrier IPv6 address cannot leak through WebRTC | Only devices you set to a VPN or Tor exit are covered. "Direct" is direct |
| Carrier-pushed firmware changes | The update and device-management engines are kept suspended | Suspending is not removing; a future firmware could behave differently |

## What it does NOT defend against
- **Your carrier knowing where you are.** The hotspot attaches to towers. Location, connection times and volumes are visible to the carrier whatever this software does.
- **Anonymity.** Mullvad sees what the carrier would otherwise see. Tor is slow and does not protect a device that logs into an account.
- **Content.** It does not look inside encrypted traffic and does not try to.
- **Someone with physical access to the unit, or already on your Wi-Fi.** Anyone on the LAN who can reach the web page can try the login; use a strong password and keep the self-signed certificate fingerprint you checked at first sign-in.
- **Malicious devices that bypass the router** (a second radio, a USB tether).
- **A vulnerability in this software or in the stock firmware under it.** The stock firmware is old, and rooting the unit is what makes this possible at all. Stone of Heimdall shrinks the exposed surface (the stock admin page is switched off for the network, SSH is key-only); it cannot make the base firmware new.

## Trust you are placing
- In the code. It was written by an AI model under the maintainer's direction and has not had an independent human security audit; the maintainer did not write or line-by-line review it. It has a large automated test suite and has run on one unit. Read before you run.
- In the third-party programs it fetches (dnsmasq, dropbear, Tor).
- In your VPN provider, if you use one.
- In the DNS-over-HTTPS resolvers (Quad9 and Cloudflare by default; plain DNS only after 60 seconds of failure unless you turn the fallback off).
- In the block-list publishers, for what gets filtered.

## Tested on
One unit of one model on one carrier. Behavior elsewhere is unknown. Reading some flash partitions can freeze the device until a power cycle (see the install notes).

## Reporting a problem
See `SECURITY.md`.
