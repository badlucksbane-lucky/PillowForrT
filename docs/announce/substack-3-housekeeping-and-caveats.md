# Keeping the box, and what it cannot do

Stone of Heimdall, firmware for the Orbic RC400L hotspot. The System section, then the limits.

## System

**Diagnostics.** One click. Every check the software can make, run on the box, network probes included. Verdict per check: fine, look, broken. Text report built for sharing: no device names, MACs, SMS, keys, passwords or full IPv6 addresses. The evaluation is a pure function of the gathered inputs; every threshold is unit-tested.

**System.** Product, firmware, kernel, uptime, load, RAM, flash partitions, temperatures, battery, services. Read from /proc, /sys and the filesystem. Not shown: IMEI, serial numbers, SIM identifiers. Factory reset not offered. Reboot confirmed twice: the page and a typed word.

**Cellular.** Read-only. APN and data settings from the stock firmware's XML. Uplink interface: addresses, CGNAT, counters. Nothing writes. An APN change can drop the data session; it stays with the carrier's flow.

**Certificate.** Self-signed, renewable while running. Auto-renews under 60 days or when it stops covering the names and addresses it must. New key, new fingerprint on every renewal. Fingerprint shown to check against the browser's.

**SSH access.** dropbear, key-only, ed25519. Authorised keys list, host key fingerprint, who may reach the port, audit trail from dropbear's RAM log. Public key lines only; no private key is generated or stored. Standard restrictions always written: no port, agent or X11 forwarding. The last key cannot be removed here.

**Scheduled actions.** Fixed list, never a command: save a snapshot, update block lists, run diagnostics, reboot. Chosen time, chosen days, schedule time zone. Missed run is skipped, not made up. Reboot needs the typed word `reboot` to create, edit or run, and is refused within 10 minutes of boot. Each run's result kept with the action and logged as an event.

**Backup.** One JSON snapshot of everything the page configures. Kept on the box (0700 dir, 0600 files), downloadable. Restore per section: wifi, pool, reservations, blocklist, firewall, dns, and the rest.

**Messages.** Read-only SMS inbox from the firmware's SQLite. Live file never opened: copied to RAM, then queried.

**Node.** Uptime, temperature, free RAM, Wi-Fi clients, uplink up or down, plan used against cap, proxy connections active and total.

**Account.** Username and password, bcrypt hash on disk. One login. Session cookie, per-session CSRF token, HTTPS only. A wrong username costs the same time as a wrong password.

## How it was made

Written by Claude, an AI model made by Anthropic, under the direction of the maintainer, who set the goals and decisions and tested on their own hardware. The maintainer did not write the code and has not audited it line by line. Large automated test suite. One unit's worth of use. Read it before you trust it with anything that matters.

## Before you trust it

One unit, one model, one carrier. Behaviour elsewhere unknown.

First-install tool is experimental. Not yet run end to end from a factory-fresh unit. Pieces tested separately. Source release. Expect to read code.

Rooting may void the warranty or breach the carrier's terms. Reading some flash partitions freezes the device until a power cycle.

Not anonymity. The carrier sees location, connection times, volume. Mullvad sees what the carrier otherwise would. Tor is slow and does not protect a device that logs into an account.

Not covered: physical access, someone on the Wi-Fi guessing the password, a device bypassing the router (second radio, USB tether), a vulnerability in the stock firmware underneath. The stock firmware is old. This shrinks the exposed surface (stock admin off for the network, ssh key-only); it cannot make the base new.

The threat model in the repo has all of this in a table with a column for where each claim stops.

## Where it is

https://github.com/badlucksbane-lucky/stone-of-heimdall

MIT. Install guide, threat model and vulnerability reporting in `docs/`. "Orbic" is the trademark of its owner, named only to say which hardware this runs on. Not affiliated with or endorsed by Orbic or any carrier. dnsmasq, dropbear and Tor fetched from their own sources, under their own licences.
