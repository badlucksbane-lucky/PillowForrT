#!/bin/bash
# set-login.sh -- set (or change) the web login for https://orbic/ . Run from a computer on the LAN. The password is typed here, sent over ssh on stdin (never on a command line) and stored on the
# Orbic only as a bcrypt hash in /data/proxy/secure/auth.json (mode 0600). Setting a login ends every open session. Minimum 10 characters.
set -eu
read -rp 'Username: ' u
case "$u" in ''|*[!A-Za-z0-9._-]*) echo "use letters, digits, . _ - only"; exit 1;; esac
read -rsp 'Password (10+ characters): ' p; echo
read -rsp 'Again: ' p2; echo
[ "$p" = "$p2" ] || { echo "the two passwords differ"; exit 1; }
printf %s "$p" | ssh -o BatchMode=yes orbic "/data/proxy/tinyfwd -set-login '$u'"
