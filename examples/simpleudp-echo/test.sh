#!/bin/bash
# simpleudp-echo scenario: run the receiver as an echo server (--swap-resp)
# and count the XDP_TX'd packets coming back on the sender.
#
# This doubles as a check for the veth XDP_TX gotcha (frames are silently
# dropped unless the peer has an XDP program attached):
# https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it
# xdperf guards against it by attaching xdp_pass_dummy / xdp_rx to its own
# device while sending (pkg/xdperf/xdperf.go runTXPacket).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export ECHO=1

source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
