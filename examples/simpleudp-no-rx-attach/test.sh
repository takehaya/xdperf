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
# See README.md for the kernel background (veth NAPI-without-XDP commits).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

main() {
    local rc=0
    scenario_preflight || rc=$?
    [ "${rc}" -eq 2 ] && return "${SKIP_EXIT_CODE}"
    [ "${rc}" -ne 0 ] && return 1

    local expected base after delta
    expected="$(to_number "${COUNT}")"

    # Phase 1: expect silent drop. GRO must actually be off — if this fails
    # and GRO stays enabled, packets would arrive and cause a false FAIL
    if ! ip netns exec "${NS_RX}" ethtool -K "${VETH_RX}" gro off >/dev/null 2>&1; then
        print_error "Failed to disable GRO on ${VETH_RX}"
        return 1
    fi
    base="$(stack_rx_packets "${NS_RX}" "${VETH_RX}")"
    print_info "Phase 1: sending ${COUNT} with no XDP attach on receiver (GRO off)"
    send_udp || return 1
    sleep 1
    after="$(stack_rx_packets "${NS_RX}" "${VETH_RX}")"
    delta=$(( after - base ))
    print_info "Phase 1: ${delta} / ${expected} packets reached ${VETH_RX}"
    if [ "${delta}" -gt $(( expected / 100 )) ]; then
        print_error "FAIL: ${delta} packets arrived without peer XDP attach (expected silent drop)"
        return 1
    fi
    print_success "Phase 1: silent drop confirmed (packets were eaten)"

    # Phase 2: expect delivery to the normal stack
    if ! ip netns exec "${NS_RX}" ethtool -K "${VETH_RX}" gro on >/dev/null 2>&1; then
        print_error "Failed to enable GRO on ${VETH_RX}"
        return 1
    fi
    base="$(stack_rx_packets "${NS_RX}" "${VETH_RX}")"
    print_info "Phase 2: sending ${COUNT} with GRO on (NAPI active)"
    send_udp || return 1
    sleep 1
    after="$(stack_rx_packets "${NS_RX}" "${VETH_RX}")"
    delta=$(( after - base ))
    ip netns exec "${NS_RX}" ethtool -K "${VETH_RX}" gro off >/dev/null 2>&1 || true
    print_info "Phase 2: ${delta} / ${expected} packets reached ${VETH_RX}"
    if [ "${delta}" -lt $(( expected * 99 / 100 )) ]; then
        print_error "FAIL: expected delivery with GRO on, got ${delta} / ${expected} packets"
        return 1
    fi
    print_success "Phase 2: delivery via NAPI confirmed"
    print_success "PASS: veth peer-attach requirement (XDP or GRO) confirmed by measurement"
    return 0
}

main
