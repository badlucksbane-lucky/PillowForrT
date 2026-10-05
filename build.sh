#!/bin/sh
# Cross-build tinyfwd for the Orbic (armv7, static). Output: ./tinyfwd
# -buildvcs=false matters: without it Go stamps the git revision into the binary
# and the hash stops matching the one on the device.
cd "$(dirname "$0")" || exit 1
GOPROXY=off GOFLAGS=-mod=vendor GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -buildvcs=false -trimpath -ldflags "-s -w" -o tinyfwd . && sha256sum tinyfwd
