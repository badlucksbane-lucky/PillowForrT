# Installing (notes, not yet a guide)

DRAFT. This describes what the software needs and how updates work. The **first install is not yet documented here**: it needs a root shell with full capabilities on the hotspot (see "First install"). Do not attempt the rest without it.

## What you need
- An Orbic RC400L hotspot you are willing to risk. Rooting may void the warranty or breach the carrier's terms; bad flash reads can freeze the unit until a power cycle. **Never read the `mtdblock1` partition.**
- A trusted computer on the hotspot's LAN, with Go to build, `ssh` and `sha256sum`.
- A written note of the unit's original settings before you change anything.

## Build
`./build.sh` builds the `tinyfwd` binary for the hotspot (ARM, one core, about 77 MB of usable memory: keep builds and extras modest).

## Updating a unit that is already set up
After the first install, updates need no cable: `scripts/deploy-tinyfwd.sh` pushes the binary over key-only SSH, checks its hash, swaps it, waits for `/status.json` and **rolls itself back** if the new binary does not answer. `scripts/guard-deploy.sh` does the same for the guard script that keeps the DNS redirect, SSH, IPv6 firewall and update suspension in place. `scripts/set-login.sh` sets the web page's username and password.

## First install

- `fork/rootshell/`: the privileged-shell binary described above.
- `fork/orbic-at/orbic.rs`: the Orbic-specific code that talks to the device's `AT+SYSCMD` channel, including how it gets a root shell onto the device in the first place. **It is not wired up.** Only this one file was pulled in; the other installer modules it imports from (`connection`, `output`, `util`, a constant it needs) were deliberately left out, so this file does not compile or run as-is. It is kept here to read and to start our own AT-channel code from, not as something to run. It is a small privileged-shell binary: once it is running on the device, it gives a root shell with the Android network groups the proxy needs.

**Getting that binary running on a stock, unrooted unit is still open.** This release does not yet document or provide the steps to deliver and launch `rootshell` on a fresh device (the privileged channel that runs it, and the bootstrap script that then installs this project). Until that is written and tested on a bare unit, there is no supported first-install path here.

## After install
Open the web page over HTTPS, compare the self-signed certificate fingerprint, sign in, and start with **watch-only** outbound mode. Look at the "would be refused" list for a few days before enforcing it.
