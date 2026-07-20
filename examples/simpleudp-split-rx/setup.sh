#!/bin/bash
# simpleudp-split-rx scenario: one xdperf process, TX and RX on different veths
# with a forwarding "DUT" namespace in between
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_root
create_netns "${NS_GEN}"
create_netns "${NS_DUT}"
create_veth_pair "${GEN_TX}" "${NS_GEN}" "${DUT_A}" "${NS_DUT}"
create_veth_pair "${DUT_B}" "${NS_DUT}" "${GEN_RX}" "${NS_GEN}"
configure_veth_v4only "${NS_GEN}" "${GEN_TX}" "${GEN_TX_IP}/24"
configure_veth_v4only "${NS_DUT}" "${DUT_A}" "${DUT_A_IP}/24"
configure_veth_v4only "${NS_DUT}" "${DUT_B}" "${DUT_B_IP}/24"
configure_veth_v4only "${NS_GEN}" "${GEN_RX}" "${GEN_RX_IP}/24"

# The DUT routes between the two subnets
ip netns exec "${NS_DUT}" sysctl -qw net.ipv4.ip_forward=1

# gen-tx transmits via XDP live-frames, and dut-a has no XDP program of its
# own — enable GRO so its NAPI is active, otherwise the veth XDP TX path
# silently drops every frame (see simpleudp-no-rx-attach/README.md)
ip netns exec "${NS_DUT}" ethtool -K "${DUT_A}" gro on

print_success "Topology ready: ${NS_GEN}(${GEN_TX}) -> ${NS_DUT}(forward) -> ${NS_GEN}(${GEN_RX})"
