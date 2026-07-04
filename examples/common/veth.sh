#!/bin/bash
# examples/common/veth.sh
# veth pair helpers (meant to be sourced)

# Delete a leftover interface of ours, but refuse to touch a same-named
# interface that is not a veth (running as root, an unconditional delete
# could take down unrelated host interfaces)
delete_veth_if_ours() {
    local dev="$1"
    ip link show dev "$dev" >/dev/null 2>&1 || return 0
    if ! ip -d link show dev "$dev" 2>/dev/null | grep -qw veth; then
        echo "Error: interface $dev exists but is not a veth; refusing to delete" >&2
        return 1
    fi
    ip link del "$dev"
}

# Create a veth pair, move each end into a namespace, and bring them up
# Usage: create_veth_pair <veth1_name> <ns1> <veth2_name> <ns2>
create_veth_pair() {
    local veth1="$1" ns1="$2" veth2="$3" ns2="$4"

    delete_veth_if_ours "$veth1"
    delete_veth_if_ours "$veth2"

    ip link add "$veth1" type veth peer name "$veth2"
    ip link set "$veth1" netns "$ns1"
    ip link set "$veth2" netns "$ns2"
    ip netns exec "$ns1" ip link set "$veth1" up
    ip netns exec "$ns2" ip link set "$veth2" up

    echo "Created veth pair: $veth1 ($ns1) <-> $veth2 ($ns2)"
}

# Assign an IPv4 address and disable IPv6 on the veth. Kernel-originated
# IPv6 frames (DAD/RS) would otherwise be counted by xdp_rx and break the
# exact-match comparison against the number of packets sent.
# Usage: configure_veth_v4only <namespace> <veth_name> <addr/prefix>
configure_veth_v4only() {
    local ns="$1" veth="$2" addr="$3"

    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.${veth}.disable_ipv6=1"
    ip netns exec "$ns" ip addr add "$addr" dev "$veth"

    echo "Configured $veth in $ns with $addr (IPv4 only)"
}
