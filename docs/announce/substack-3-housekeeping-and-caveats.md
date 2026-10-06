# Stone of Heimdall, part 3 of 3: housekeeping, and what to read before you trust it

Parts 1 and 2 covered the privacy and watching halves of the Stone of Heimdall page. This last part covers the System section, the cards that keep the box itself healthy, and then the caveats.

## System

### Diagnostics

One click runs every check the software can make about the box and says, in plain words, what is fine, what deserves a look and what is broken. The checks run on the hotspot itself, network probes included. The text report is written for sharing: it contains no device names, MAC addresses, messages, keys, passwords or full IPv6 addresses.

### System

What the box is and how it is doing, read straight from the kernel: uptime, temperature, memory, battery, storage. Deliberately absent: the IMEI, serial numbers and SIM identifiers, because the page never needs them. Factory reset is not offered at all. Reboot needs a typed confirmation.

### Cellular

Read-only: the APN and data settings the stock firmware keeps, and what the kernel shows of the uplink, including carrier-grade NAT and counters. Nothing here writes. An APN change can cut the hotspot off, so it is left to the carrier's own flow.

### Certificate

The page's self-signed HTTPS certificate, renewable while running. It renews itself when under sixty days remain or when it stops covering the names it must. A renewal makes a new key and a new fingerprint, and the card shows the current one so you can check it against what your browser pinned.

### SSH access

The authorised keys of the key-only SSH login, the host key fingerprint, who may reach the port, and an audit trail of logins and failures. Adding a key takes a public key line only; private keys are never generated or stored here. The last key can never be removed from this page, because that would lock SSH out.

### Scheduled actions

Things the box does by itself at a chosen time on chosen days, from a short fixed list, never an arbitrary command: save a settings snapshot, update the block lists, run the diagnostics, or reboot. A missed run is skipped, not made up later. A reboot needs the typed word to create, and is refused within ten minutes of boot so a bad schedule cannot become a reboot loop.

### Backup

Settings snapshots: one file holding everything this page configures, kept on the box and downloadable to keep a copy off it, since a factory reset or firmware update can wipe the flash. Restore is per section, so you can bring back the Wi-Fi settings without touching the firewall.

### Messages

A read-only SMS inbox, because the hotspot has a SIM and the carrier sends messages to it. The live database is never opened directly; a copy is read from a RAM disk.

### Node

A small status table for the box as a node: uptime, temperature, free memory, Wi-Fi clients, data used this billing cycle against your plan, and the last heartbeat from a companion computer if you run one.

### Account

Change the login password. There is one account, sessions are cookies over HTTPS only, and a wrong username costs the same time as a wrong password.

## How it was made

The code was written by Claude, an AI model made by Anthropic, under the direction of the project's maintainer, who set the goals and the decisions and tested the result on their own hardware. The maintainer did not write the code and has not audited it line by line. It has a large automated test suite and one real unit's worth of use. Read it before you trust it with anything that matters.

## Before you install

- **It has run on one unit** of one model on one carrier. Behaviour elsewhere is unknown.
- **The first-install tool is experimental** and has not yet been run end to end from a factory-fresh unit. Its pieces were tested separately. It installs over USB, journals every change and rolls back on failure, but you should read the install guide and expect to read code.
- **Rooting the hotspot** may void its warranty or breach your carrier's terms. Reading some flash partitions can freeze the device until a power cycle.
- **It is not anonymity.** The carrier knows where the hotspot is and sees connection metadata. The VPN provider sees what the carrier otherwise would. Tor is slow and does not protect a device that logs into an account.
- **It does not protect against** someone with physical access, someone already on your Wi-Fi who guesses the password, devices that bypass the router with a second radio or a USB tether, or a vulnerability in the old stock firmware underneath.

The threat model in the repository says all of this in a table, with a column for where each claim stops.

## Where to get it

The source is on GitHub under the MIT licence, with the install guide, the threat model and how to report a vulnerability in the docs folder:

https://github.com/badlucksbane-lucky/stone-of-heimdall

"Orbic" is the trademark of its owner and appears here only to say which hardware this runs on. The project is not affiliated with or endorsed by Orbic or any carrier. The third-party programs it installs, dnsmasq, dropbear and Tor, are fetched from their own sources and keep their own licences.
