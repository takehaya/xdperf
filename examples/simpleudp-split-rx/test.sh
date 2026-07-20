#!/bin/bash
# examples/simpleudp-split-rx/test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_root
check_xdperf_built

if ! ip netns pids "${NS_GEN}" >/dev/null 2>&1 || ! ip netns pids "${NS_DUT}" >/dev/null 2>&1; then
    print_error "netns not found. Run setup.sh first"
    exit 1
fi

lf=0
check_live_frames "${NS_GEN}" "${GEN_TX}" || lf=$?
if [ "${lf}" -eq 2 ]; then
    print_error "xdperf probe failed on ${GEN_TX} (not a kernel-support SKIP)"
    exit 1
fi
if [ "${lf}" -eq 1 ]; then
    print_info "SKIP: this kernel does not support XDP live-frames (BPF_PROG_RUN)"
    exit "${SKIP_EXIT_CODE}"
fi

# Frames must be addressed to the DUT's L2 hop; the plugin default is
# broadcast, which Linux does not forward
DUT_MAC="$(ip netns exec "${NS_DUT}" cat "/sys/class/net/${DUT_A}/address")"

# gen-rx's rx_queue_*_xdp_packets counters vanish when the process exits and
# detaches xdp_rx, so the persistent forwarding evidence is the DUT's egress
# counter toward gen-rx
dutb_base="$(ip netns exec "${NS_DUT}" cat "/sys/class/net/${DUT_B}/statistics/tx_packets")"

cfg="{\"src_ip\":\"${GEN_TX_IP}\",\"dst_ip\":\"${GEN_RX_IP}\",\"dst_port\":${DST_PORT},\"payload_size\":${PAYLOAD_SIZE},\"is_arp_resolve\":false,\"dst_mac\":\"${DUT_MAC}\"}"

print_info "Sending: count=${COUNT} pps=${PPS} plugin=${PLUGIN} tx=${GEN_TX} rx=${GEN_RX} cfg=${cfg}"
if ! ip netns exec "${NS_GEN}" "${XDPERF_BIN}" run \
    --device "${GEN_TX}" --rx-device "${GEN_RX}" \
    --plugin "${PLUGIN}" --plugin-path "${PLUGIN_PATH}" \
    --count "${COUNT}" --pps "${PPS}" \
    --cfg "${cfg}" > "${TX_LOG}" 2>&1; then
    print_error "Send failed (log: ${TX_LOG})"
    tail -n 20 "${TX_LOG}"
    exit 1
fi

sleep 1
dutb_after="$(ip netns exec "${NS_DUT}" cat "/sys/class/net/${DUT_B}/statistics/tx_packets")"
delta=$(( dutb_after - dutb_base ))
expected="$(to_number "${COUNT}")"
required=$(( expected * PASS_THRESHOLD / 100 ))
# ARP resolution on the dut-b <-> gen-rx link adds a handful of frames on top
margin=16

print_info "DUT forwarded ${delta} packets toward ${GEN_RX} (sent ${expected}, threshold ${PASS_THRESHOLD}%)"
if [ "${delta}" -lt "${required}" ] || [ "${delta}" -gt $(( expected + margin )) ]; then
    print_error "FAIL: DUT forwarded ${delta} / expected ${required}..$(( expected + margin ))"
    print_error "tx log tail:"
    tail -n 10 "${TX_LOG}" 2>/dev/null || true
    exit 1
fi

# The same process must also have counted on the RX device: the send+recv
# stats lines report a nonzero recv/s while xdp_rx (on gen-rx) sees traffic
# (rates are printed with thousands separators, e.g. "10,000 recv/s")
if ! grep -qE '[1-9][0-9,]* recv/s' "${TX_LOG}"; then
    print_error "FAIL: no nonzero recv/s in ${TX_LOG} — xdp_rx on ${GEN_RX} did not count"
    tail -n 10 "${TX_LOG}" 2>/dev/null || true
    exit 1
fi

print_success "PASS: one process transmitted on ${GEN_TX} and counted on ${GEN_RX}"
exit 0
