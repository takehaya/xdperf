#!/bin/bash
# tcp-netkit: build a 3-namespace topology (veth sender -> DUT router -> netkit L2 & L3 Pods)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_root
stop_nk_processes

create_netns "${NS_TX}"
create_netns "${NS_DUT}"
create_netns "${NS_RX_L2}"
create_netns "${NS_RX_L3}"

# Sender (veth) <-> DUT ingress (veth)
create_veth_pair "${VETH_TX}" "${NS_TX}" "${VETH_DUT}" "${NS_DUT}"
configure_veth_v4only "${NS_TX}" "${VETH_TX}" "${TX_IP4}/24"
configure_veth_v4only "${NS_DUT}" "${VETH_DUT}" "${DUT_IN_IP4}/24"
ip -n "${NS_TX}" route add 10.200.2.0/24 via "${DUT_IN_IP4}"
ip -n "${NS_TX}" route add 10.200.3.0/24 via "${DUT_IN_IP4}"

# If the kernel or iproute2 does not support netkit, leave the base namespaces
# in place so test.sh can report SKIP cleanly and teardown.sh can clean up.
if ! ip -n "${NS_DUT}" link add "${NK_DUT_L2}" type netkit mode l2 peer "${NK_RX_L2}" netns "${NS_RX_L2}" 2>/dev/null; then
    print_info "netkit not supported on this kernel/iproute2; test.sh will SKIP"
    exit 0
fi

# DUT <-> RX Pod 1 (netkit L2 mode)
ip netns exec "${NS_DUT}" sysctl -qw "net.ipv6.conf.${NK_DUT_L2}.disable_ipv6=1"
ip netns exec "${NS_RX_L2}" sysctl -qw "net.ipv6.conf.${NK_RX_L2}.disable_ipv6=1"
ip -n "${NS_DUT}" addr add "${DUT_L2_IP4}/24" dev "${NK_DUT_L2}"
ip -n "${NS_DUT}" link set "${NK_DUT_L2}" up
ip -n "${NS_RX_L2}" addr add "${RX_L2_IP4}/24" dev "${NK_RX_L2}"
ip -n "${NS_RX_L2}" link set "${NK_RX_L2}" up
ip -n "${NS_RX_L2}" route add 10.200.1.0/24 via "${DUT_L2_IP4}"

# DUT <-> RX Pod 2 (netkit L3 mode, Cilium default style)
ip -n "${NS_DUT}" link add "${NK_DUT_L3}" type netkit mode l3 peer "${NK_RX_L3}" netns "${NS_RX_L3}"
ip netns exec "${NS_DUT}" sysctl -qw "net.ipv6.conf.${NK_DUT_L3}.disable_ipv6=1"
ip netns exec "${NS_RX_L3}" sysctl -qw "net.ipv6.conf.${NK_RX_L3}.disable_ipv6=1"
ip -n "${NS_DUT}" link set "${NK_DUT_L3}" up
ip -n "${NS_DUT}" route add "${RX_L3_IP4}/32" dev "${NK_DUT_L3}"
ip -n "${NS_RX_L3}" addr add "${RX_L3_IP4}/32" dev "${NK_RX_L3}"
ip -n "${NS_RX_L3}" link set "${NK_RX_L3}" up
ip -n "${NS_RX_L3}" route add default dev "${NK_RX_L3}"

ip netns exec "${NS_DUT}" sysctl -qw net.ipv4.ip_forward=1

print_success "Topology ready: ${NS_TX}(veth) -> ${NS_DUT} -> ${NS_RX_L2}(netkit L2) & ${NS_RX_L3}(netkit L3)"
