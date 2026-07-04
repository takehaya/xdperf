#!/bin/bash
# simpleudp-vlan scenario: send UDP with an outer 802.1Q tag and verify with
# the receiver-side XDP counter (xdp_rx strips VLAN tags before parsing)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Outer 802.1Q tag (vlan_id != 0 enables tagging)
export VLAN_ID="${VLAN_ID:-100}"
export VLAN_PCP="${VLAN_PCP:-3}"

source "${SCRIPT_DIR}/../common/udp_scenario.sh"

run_udp_test
