# Keeping the box, and what it cannot do

Stone of Heimdall, firmware for the Orbic RC400L hotspot. The System section, then the limits.

## System

**Diagnostics.** One click runs every check the software can make and says, in plain words, what is fine, what deserves a look, what is broken. The checks run on the box, network probes included. The text report is written to be shared: no device names, MACs, messages, keys, passwords or full IPv6 addresses.

**System.** What the box is and how it is doing, read straight from the kernel: uptime, temperature, memory, battery, storage. Deliberately absent: the IMEI, serial numbers and SIM identifiers, because the page never needs them. Factory reset is not offered. Reboot needs a typed confirmation.

**Cellular.** Read-only: the APN and data settings the stock firmware keeps, and the kernel's view of the uplink, carrier-grade NAT and counters included. Nothing here writes. An APN change can cut the box off, so it is left to the carrier's own flow.

**Certificate.** The page's self-signed certificate, renewable while running. It renews itself under sixty days, or when it stops covering the names it must. A renewal makes a new key and a new fingerprint. The card shows the current one to check against what your browser pinned.

**SSH access.** The authorised keys of the key-only root login, the host key fingerprint, who may reach the port, and an audit trail of logins and failures. Adding takes a public key line only. Private keys are never generated or stored here. The last key cannot be removed from this page, because that would lock ssh out.

**Scheduled actions.** Things the box does by itself at a chosen time on chosen days, from a short fixed list, never an arbitrary command: save a snapshot, update the block lists, run the diagnostics, reboot. A missed run is skipped, not made up. A reboot needs the typed word to create, and is refused within ten minutes of boot so a bad schedule cannot become a reboot loop.

**Backup.** Settings snapshots: one file holding everything the page configures, kept on the box and downloadable, because a factory reset or a firmware update can wipe the flash. Restore is per section. The Wi-Fi settings can come back without touching the firewall.

**Messages.** A read-only SMS inbox. The hotspot has a SIM and the carrier writes to it. The live database is never opened; a copy is read from RAM.

**Node.** Uptime, temperature, free memory, Wi-Fi clients, whether the uplink is up, data used this billing cycle against the plan, and the proxy's connection counts.

**Account.** Change the password. One login. Sessions are cookies over HTTPS only. A wrong username costs the same time as a wrong password.

## How it was made

The code was written by Claude, an AI model made by Anthropic, under the direction of the maintainer, who set the goals and the decisions and tested the result on their own hardware. The maintainer did not write the code and has not audited it line by line. It has a large automated test suite and one unit's worth of use. Read it before you trust it with anything that matters.

## Before you trust it

It has run on one unit of one model on one carrier. Behaviour elsewhere is unknown.

The first-install tool is experimental. It has not yet been run end to end from a factory-fresh unit; its pieces were tested separately. It is a source release. Expect to read code.

Rooting the hotspot may void its warranty or breach the carrier's terms. Reading some flash partitions can freeze the device until a power cycle.

It is not anonymity. The carrier knows where the hotspot is and sees connection metadata. The VPN provider sees what the carrier otherwise would. Tor is slow and does not protect a device that logs into an account.

It does not protect against someone with physical access, someone already on the Wi-Fi who guesses the password, a device that bypasses the router through a second radio or a USB tether, or a vulnerability in the old stock firmware underneath.

The threat model in the repository says all of this in a table, with a column for where each claim stops.

## Where it is

Source, install guide, threat model and how to report a vulnerability:

https://github.com/badlucksbane-lucky/stone-of-heimdall

MIT licence. "Orbic" is the trademark of its owner and appears here only to say which hardware this runs on. Not affiliated with or endorsed by Orbic or any carrier. dnsmasq, dropbear and Tor are fetched from their own sources and keep their own licences.
