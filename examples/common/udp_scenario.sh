#!/bin/bash
# examples/common/udp_scenario.sh
# Shared implementation for the simpleudp-family scenarios (meant to be sourced)
#
# Topology:
#   ns: xdperf-tx                     ns: xdperf-rx
#   +----------------+   veth pair   +----------------+
#   | xdp-tx         |===============| xdp-rx         |
#   | 192.168.100.1  |               | 192.168.100.2  |
#   | live-frames TX |               | xdp_rx attach  |
#   +----------------+               +----------------+
#
# The receive server is started before transmitting: the veth XDP TX path
# requires the peer's NAPI to be active (XDP program attached or GRO on).
# See examples/README.md and simpleudp-no-rx-attach/README.md for details.
#
# Overridable via environment variables:
#   COUNT (10k) / PPS (10k) / PAYLOAD_SIZE (256) / DST_PORT (10001)
#   PLUGIN (simpleudp.tinygo) / VLAN_ID (0=untagged) / VLAN_PCP (0)
#   ECHO (0) / ECHO_THRESHOLD (99) / PASS_THRESHOLD (100)

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="${EXAMPLES_DIR:-$(cd "${COMMON_DIR}/.." && pwd)}"

source "${COMMON_DIR}/test_utils.sh"
source "${COMMON_DIR}/netns.sh"
source "${COMMON_DIR}/veth.sh"

NS_TX="${NS_TX:-xdperf-tx}"
NS_RX="${NS_RX:-xdperf-rx}"
VETH_TX="${VETH_TX:-xdp-tx}"
VETH_RX="${VETH_RX:-xdp-rx}"
TX_IP="${TX_IP:-192.168.100.1}"
RX_IP="${RX_IP:-192.168.100.2}"

COUNT="${COUNT:-10k}"
PPS="${PPS:-10k}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-256}"
DST_PORT="${DST_PORT:-10001}"
PLUGIN="${PLUGIN:-simpleudp.tinygo}"
VLAN_ID="${VLAN_ID:-0}"
VLAN_PCP="${VLAN_PCP:-0}"
PASS_THRESHOLD="${PASS_THRESHOLD:-100}"
# ECHO=1: run the receiver as an echo server (--swap-resp) and count the
# XDP_TX'd packets coming back on the sender (see simpleudp-echo/README.md).
# Echoes arriving after the sender exits (XDP detached) are not counted,
# hence the 99% default threshold.
ECHO="${ECHO:-0}"
ECHO_THRESHOLD="${ECHO_THRESHOLD:-99}"

RX_LOG="${RX_LOG:-/tmp/xdperf-example-rx.log}"
TX_LOG="${TX_LOG:-/tmp/xdperf-example-tx.log}"

# Convert "10k" / "1m" / "10000" to a plain number
to_number() {
    local v="$1"
    case "$v" in
        *k) echo $(( ${v%k} * 1000 )) ;;
        *m) echo $(( ${v%m} * 1000000 )) ;;
        *) echo "$v" ;;
    esac
}

setup_udp_topology() {
    check_root
    create_netns "${NS_TX}"
    create_netns "${NS_RX}"
    create_veth_pair "${VETH_TX}" "${NS_TX}" "${VETH_RX}" "${NS_RX}"
    configure_veth_v4only "${NS_TX}" "${VETH_TX}" "${TX_IP}/24"
    configure_veth_v4only "${NS_RX}" "${VETH_RX}" "${RX_IP}/24"
    print_success "Topology ready: ${NS_TX}(${VETH_TX}) <-> ${NS_RX}(${VETH_RX})"
}

teardown_udp_topology() {
    check_root
    stop_rx_server
    delete_netns "${NS_TX}"
    delete_netns "${NS_RX}"
    print_success "Topology removed"
}

run_udp_test() {
    check_root
    check_xdperf_built

    if ! ip netns pids "${NS_TX}" >/dev/null 2>&1 || ! ip netns pids "${NS_RX}" >/dev/null 2>&1; then
        print_error "netns not found. Run setup.sh first"
        return 1
    fi

    if ! check_live_frames "${NS_TX}" "${VETH_TX}"; then
        print_info "SKIP: this kernel does not support XDP live-frames (BPF_PROG_RUN)"
        return 0
    fi

    local rx_args=()
    if [ "${ECHO}" -eq 1 ]; then
        rx_args+=(--swap-resp)
    fi
    start_rx_server "${NS_RX}" "${VETH_RX}" "${RX_LOG}" "${rx_args[@]}" || return 1

    # veth counters are cumulative; measure deltas from a baseline
    local base after delta expected
    base="$(rx_xdp_packets "${NS_RX}" "${VETH_RX}")"
    local echo_base echo_after echo_delta
    echo_base="$(rx_xdp_packets "${NS_TX}" "${VETH_TX}")"

    # ECHO: run the sender in send+receive mode so xdperf attaches xdp_rx to
    # xdp-tx, which both counts the echoes and satisfies the peer-attach
    # requirement for the XDP_TX return path
    local tx_args=()
    if [ "${ECHO}" -eq 1 ]; then
        tx_args+=(--recv)
    fi

    local cfg="{\"src_ip\":\"${TX_IP}\",\"dst_ip\":\"${RX_IP}\",\"dst_port\":${DST_PORT},\"payload_size\":${PAYLOAD_SIZE},\"is_arp_resolve\":false"
    if [ "${VLAN_ID}" -ne 0 ]; then
        cfg+=",\"vlan_id\":${VLAN_ID},\"vlan_pcp\":${VLAN_PCP}"
    fi
    cfg+="}"

    print_info "Sending: count=${COUNT} pps=${PPS} plugin=${PLUGIN} echo=${ECHO} cfg=${cfg}"
    if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
        --plugin "${PLUGIN}" --plugin-path "${PLUGIN_PATH}" \
        --count "${COUNT}" --pps "${PPS}" "${tx_args[@]}" \
        --cfg "${cfg}" > "${TX_LOG}" 2>&1; then
        print_error "Send failed (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        stop_rx_server
        return 1
    fi

    sleep 1
    after="$(rx_xdp_packets "${NS_RX}" "${VETH_RX}")"
    echo_after="$(rx_xdp_packets "${NS_TX}" "${VETH_TX}")"
    stop_rx_server

    delta=$(( after - base ))
    expected="$(to_number "${COUNT}")"
    local required=$(( expected * PASS_THRESHOLD / 100 ))

    print_info "Sent ${expected} packets / received ${delta} packets (threshold: ${PASS_THRESHOLD}%)"
    if [ "${delta}" -lt "${required}" ] || [ "${delta}" -gt "${expected}" ]; then
        print_error "FAIL: received ${delta} / expected ${expected} (minimum ${required})"
        print_error "rx log tail:"
        tail -n 10 "${RX_LOG}" 2>/dev/null || true
        return 1
    fi

    if [ "${ECHO}" -eq 1 ]; then
        echo_delta=$(( echo_after - echo_base ))
        local echo_required=$(( expected * ECHO_THRESHOLD / 100 ))
        print_info "Echoes received (XDP_TX return) ${echo_delta} packets (threshold: ${ECHO_THRESHOLD}%)"
        if [ "${echo_delta}" -lt "${echo_required}" ] || [ "${echo_delta}" -gt "${expected}" ]; then
            print_error "FAIL: echoes received ${echo_delta} / expected ${expected} (minimum ${echo_required})"
            print_error "Note: veth XDP_TX is dropped unless the peer has an XDP program attached"
            tail -n 10 "${RX_LOG}" 2>/dev/null || true
            return 1
        fi
    fi

    print_success "PASS: receive counters match"
    return 0
}

# Negative case: no XDP program attached on the peer (receiver) side.
# Phase 1: no XDP attach, GRO off -> frames are silently dropped
# Phase 2: GRO on -> peer NAPI becomes active, frames reach the normal stack
# See simpleudp-no-rx-attach/README.md for the kernel background.
run_no_rx_attach_test() {
    check_root
    check_xdperf_built

    if ! ip netns pids "${NS_TX}" >/dev/null 2>&1 || ! ip netns pids "${NS_RX}" >/dev/null 2>&1; then
        print_error "netns not found. Run setup.sh first"
        return 1
    fi

    if ! check_live_frames "${NS_TX}" "${VETH_TX}"; then
        print_info "SKIP: this kernel does not support XDP live-frames (BPF_PROG_RUN)"
        return 0
    fi

    local cfg="{\"src_ip\":\"${TX_IP}\",\"dst_ip\":\"${RX_IP}\",\"dst_port\":${DST_PORT},\"payload_size\":${PAYLOAD_SIZE},\"is_arp_resolve\":false}"
    local expected base after delta
    expected="$(to_number "${COUNT}")"

    send_once() {
        ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
            --plugin "${PLUGIN}" --plugin-path "${PLUGIN_PATH}" \
            --count "${COUNT}" --pps "${PPS}" \
            --cfg "${cfg}" > "${TX_LOG}" 2>&1
    }

    # Phase 1: expect silent drop
    ip netns exec "${NS_RX}" ethtool -K "${VETH_RX}" gro off >/dev/null 2>&1 || true
    base="$(stack_rx_packets "${NS_RX}" "${VETH_RX}")"
    print_info "Phase 1: sending ${COUNT} with no XDP attach on receiver (GRO off)"
    if ! send_once; then
        print_error "Send failed (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        return 1
    fi
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
    ip netns exec "${NS_RX}" ethtool -K "${VETH_RX}" gro on >/dev/null 2>&1
    base="$(stack_rx_packets "${NS_RX}" "${VETH_RX}")"
    print_info "Phase 2: sending ${COUNT} with GRO on (NAPI active)"
    if ! send_once; then
        print_error "Send failed (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        return 1
    fi
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
