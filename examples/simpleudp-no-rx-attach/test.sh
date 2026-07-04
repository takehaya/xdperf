#!/bin/bash
# simpleudp-no-rx-attach scenario: measure what happens when the receiver
# has no XDP program attached.
#
# The veth XDP transmit path silently drops frames unless the peer's NAPI is
# active (XDP program attached or GRO on):
# https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it
#
# Phase 1: no XDP attach, GRO off -> expect ~0 packets to arrive (dropped)
# Phase 2: GRO on -> expect delivery to the normal network stack
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_no_rx_attach_test
