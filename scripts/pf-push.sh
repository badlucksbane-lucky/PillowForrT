#!/bin/bash
# pf-push.sh <local-file> <remote-path> [mode]   -- copy a file to the box over SSH (`ssh pillowforrt`, key-only root on 192.168.1.254, from a trusted computer).
# dropbear has no sftp server, so this streams through `cat` and moves the file into place atomically (write .new, chmod, rename). It replaces the old
# adb push + AT+SYSCMD dance for everything except the very first install. Example: pf-push.sh tinyfwd /data/proxy/tinyfwd.new 755
set -eu
SRC="${1:?usage: pf-push.sh <local-file> <remote-path> [mode]}"; DST="${2:?remote path}"; MODE="${3:-644}"
ssh -o BatchMode=yes pillowforrt "cat > '$DST.part' && chmod $MODE '$DST.part' && mv '$DST.part' '$DST'" < "$SRC"
ssh -o BatchMode=yes pillowforrt "ls -l '$DST'; sha256sum '$DST' | cut -c1-16"; echo "local: $(sha256sum "$SRC" | cut -c1-16)"
