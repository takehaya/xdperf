#!/bin/bash
# srv6 scenario: send SRv6-encapsulated traffic (all three modes) across the
# veth pair and verify with the receiver-side XDP counter.
#
# The plugin builds the whole frame (outer IPv6 + SRH + inner packet) with a
# static destination MAC, so no IPv6 stack is needed on the veths; the
# receiver counts every arriving frame at XDP level.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/udp_scenario.sh"

PLUGIN="srv6.go"
MODES=(l3vpn_ipv4 l2vpn_eth ipv6)
SEGMENTS='["2001:db8:100::1","2001:db8:200::1"]'

# Plugin config for one mode: 2-segment SID list, flow-label + inner-port
# sweeps, IMIX sizes above every mode's minimum (122..142 with 2 segments).
build_srv6_cfg() {
    local mode="$1" dst_mac="$2"
    echo "{\"mode\":\"${mode}\",\"segments\":${SEGMENTS},\"src_ip\":\"2001:db8::1\",\"dst_mac\":\"${dst_mac}\",\"is_arp_resolve\":false,\"flow_label_start\":0,\"flow_label_end\":1000,\"vary_inner_src_port\":true,\"imix_sizes\":[256,768,1400],\"imix_weights\":[7,2,1]}"
}

run_srv6_test() {
    local rc=0
    scenario_preflight || rc=$?
    [ "${rc}" -eq 2 ] && return "${SKIP_EXIT_CODE}"
    [ "${rc}" -ne 0 ] && return 1

    local dst_mac
    dst_mac="$(ip netns exec "${NS_RX}" cat "/sys/class/net/${VETH_RX}/address")"

    start_rx_server "${NS_RX}" "${VETH_RX}" "${RX_LOG}" || return 1

    local expected base after delta failed=0
    expected="$(to_number "${COUNT}")"
    for mode in "${MODES[@]}"; do
        base="$(rx_xdp_packets "${NS_RX}" "${VETH_RX}")"
        local cfg
        cfg="$(build_srv6_cfg "${mode}" "${dst_mac}")"
        print_info "Sending: mode=${mode} count=${COUNT} pps=${PPS} cfg=${cfg}"
        if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
            --plugin "${PLUGIN}" --plugin-path "${PLUGIN_PATH}" \
            --count "${COUNT}" --pps "${PPS}" \
            --cfg "${cfg}" > "${TX_LOG}" 2>&1; then
            print_error "Send failed for mode=${mode} (log: ${TX_LOG})"
            tail -n 20 "${TX_LOG}"
            failed=1
            continue
        fi
        sleep 1
        after="$(rx_xdp_packets "${NS_RX}" "${VETH_RX}")"
        delta=$(( after - base ))
        print_info "mode=${mode}: sent ${expected} / received ${delta}"
        if [ "${delta}" -ne "${expected}" ]; then
            print_error "FAIL: mode=${mode} received ${delta} / expected ${expected}"
            tail -n 10 "${RX_LOG}" 2>/dev/null || true
            failed=1
        fi
    done

    stop_rx_server
    [ "${failed}" -ne 0 ] && return 1
    print_success "PASS: all ${#MODES[@]} SRv6 modes received exactly"
    return 0
}

run_srv6_test
