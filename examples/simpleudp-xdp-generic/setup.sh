#!/bin/bash
# simpleudp-xdp-generic scenario: build the topology
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

setup_udp_topology

# Generic (SKB) mode does not activate the veth peer NAPI the way a native
# attach does, and the veth XDP transmit path silently drops frames unless
# the peer's NAPI is active. Enable GRO on the receiver to activate NAPI
# (same mechanism as simpleudp-no-rx-attach Phase 2).
ip netns exec "${NS_RX}" ethtool -K "${VETH_RX}" gro on
print_success "GRO enabled on ${VETH_RX} (NAPI active for generic mode RX)"
