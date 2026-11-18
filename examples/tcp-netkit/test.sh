#!/bin/bash
# tcp-netkit: verify guardrail on netkit TX and end-to-end TCP / mixed traffic
# into netkit (L2 and L3) Pod namespaces.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

check_root
check_xdperf_built
if [ ! -x "${SINK_BIN}" ]; then
    print_error "xdperf-sink not found: ${SINK_BIN} (run 'make build' at the repo root)"
    exit 1
fi

if ! ip -n "${NS_TX}" link show "${VETH_TX}" >/dev/null 2>&1 || ! ip -n "${NS_DUT}" link show "${VETH_DUT}" >/dev/null 2>&1; then
    print_error "Topology not found. Run setup.sh first"
    exit 1
fi

if ! ip -n "${NS_RX_L2}" link show "${NK_RX_L2}" >/dev/null 2>&1; then
    print_info "SKIP: netkit is not available on this kernel/iproute2"
    exit "${SKIP_EXIT_CODE}"
fi

lf=0
check_live_frames "${NS_TX}" "${VETH_TX}" || lf=$?
if [ "${lf}" -eq 2 ]; then
    print_error "xdperf probe failed on ${VETH_TX}"
    exit 1
fi
if [ "${lf}" -eq 1 ]; then
    print_info "SKIP: this kernel does not support XDP live-frames (BPF_PROG_RUN)"
    exit "${SKIP_EXIT_CODE}"
fi

cleanup_test() {
    ip netns exec "${NS_DUT}" sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
    stop_nk_processes
}
trap cleanup_test EXIT

start_dut_helper() {
    stop_pidfile "${PASS_PID_FILE}" xdperf-sink
    : > "${PASS_LOG}"
    setsid ip netns exec "${NS_DUT}" "${SINK_BIN}" -proto udp -listen 127.0.0.1:1 -interval 0 \
        -xdp-pass-dev "${VETH_DUT}" "$@" > "${PASS_LOG}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PASS_PID_FILE}"
    local i
    for i in $(seq 1 50); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            print_error "DUT helper exited early (log: ${PASS_LOG})"
            cat "${PASS_LOG}" 2>/dev/null || true
            rm -f "${PASS_PID_FILE}"
            return 1
        fi
        if ip netns exec "${NS_DUT}" ip -d link show dev "${VETH_DUT}" 2>/dev/null | grep -q "prog/xdp" &&
           grep -q "listening" "${PASS_LOG}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    print_error "DUT helper did not become ready in ${NS_DUT} (log: ${PASS_LOG})"
    cat "${PASS_LOG}" 2>/dev/null || true
    return 1
}

# 1. Negative check: attempting to transmit directly on a netkit interface must
# fail immediately with a clear error instead of silently dropping frames.
print_info "Case 1 (guardrail): verifying direct TX on netkit (${NK_RX_L2}) is rejected"
guard_log="${XDPERF_EXAMPLE_RUNDIR}/nk-guardrail.log"
if ip netns exec "${NS_RX_L2}" "${XDPERF_BIN}" run --device "${NK_RX_L2}" \
    --count 10 --parallelism 1 --plugin simpleudp.tinygo --plugin-path "${PLUGIN_PATH}" \
    > "${guard_log}" 2>&1; then
    print_error "FAIL: xdperf run unexpectedly succeeded on netkit device ${NK_RX_L2}"
    exit 1
fi
if ! grep -q "does not support native XDP or ndo_xdp_xmit" "${guard_log}"; then
    print_error "FAIL: unexpected error message on netkit device (log: ${guard_log}):"
    cat "${guard_log}"
    exit 1
fi
print_success "Case 1 PASS: direct live-frame TX on netkit rejected with guidance"

# Attach pass-through XDP on the DUT's ingress veth so its NAPI wakes for
# live-frame XDP_TX packets coming from NS_TX.
start_dut_helper

start_nk_sink() {
    local ns="$1" listen="$2"
    stop_pidfile "${SINK_PID_FILE}" xdperf-sink
    : > "${SINK_LOG}"
    setsid ip netns exec "$ns" "${SINK_BIN}" -listen "$listen" -interval 0 > "${SINK_LOG}" 2>&1 &
    echo "$!" > "${SINK_PID_FILE}"
    local i
    for i in $(seq 1 50); do
        if grep -q "listening" "${SINK_LOG}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    print_error "xdperf-sink did not become ready in ${ns} (log: ${SINK_LOG})"
    cat "${SINK_LOG}" 2>/dev/null || true
    return 1
}

verify_tcp_flows() {
    local report_path="$1" sink_path="$2" flows="$3" expected_bytes="$4"
    python3 - "${report_path}" "${sink_path}" "${flows}" "${expected_bytes}" <<'PY'
import csv, json, sys
report_path, sink_path, flows, expected_bytes = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with open(report_path, newline='') as f:
    rows = list(csv.DictReader(f))
with open(sink_path) as f:
    sink = json.loads(f.readlines()[-1])
assert len(rows) == flows, f"rows={len(rows)} != {flows}"
assert all(r['state'] == 'done' for r in rows), rows
assert sum(int(r['bytes_acked']) for r in rows) == expected_bytes, rows
assert sink['accepted'] == sink['closed'] == flows, sink
assert sink['bytes'] == expected_bytes, sink
PY
}

# 2. TCP stream into netkit L3 Pod (Cilium default L3 mode)
print_info "Case 2 (netkit L3): ${FLOWS} TCP flows x ${BYTES} bytes -> ${RX_L3_IP4}:${DST_PORT}"
ip netns exec "${NS_TX}" ping -c 1 -W 1 "${RX_L3_IP4}" >/dev/null
start_nk_sink "${NS_RX_L3}" "${RX_L3_IP4}:${DST_PORT}"
report_l3="${XDPERF_EXAMPLE_RUNDIR}/nk-l3-flows.csv"
cfg_l3="{\"dst_ip\":\"${RX_L3_IP4}\",\"tcp_port\":${DST_PORT},\"flows\":${FLOWS},\"bytes\":\"${BYTES}\",\"window_segs\":${WINDOW}}"
if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
    --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" --plugin-config "${cfg_l3}" \
    --parallelism "${PARALLELISM}" --tcp-flow-report "${report_l3}" > "${TX_LOG}" 2>&1; then
    print_error "FAIL: netkit L3 TCP run failed (log: ${TX_LOG})"
    tail -n 25 "${TX_LOG}"
    exit 1
fi
stop_pidfile "${SINK_PID_FILE}" xdperf-sink

expected_bytes=$(( BYTES * FLOWS ))
verify_tcp_flows "${report_l3}" "${SINK_LOG}" "${FLOWS}" "${expected_bytes}"
print_success "Case 2 PASS: ${FLOWS} TCP flows (${expected_bytes} bytes) verified into netkit L3 Pod"

# 3. Mixed UDP + unequal TCP flows into netkit L2 Pod
print_info "Case 3 (netkit L2 mixed): DNS UDP + 4 TCP flows -> ${RX_L2_IP4}:${DST_PORT}"
ip netns exec "${NS_TX}" ping -c 1 -W 1 "${RX_L2_IP4}" >/dev/null
start_nk_sink "${NS_RX_L2}" "${RX_L2_IP4}:${DST_PORT}"
udp_log="${XDPERF_EXAMPLE_RUNDIR}/nk-l2-udp.json"
: > "${udp_log}"
setsid ip netns exec "${NS_RX_L2}" python3 "${TCP_PY_DIR}/udp_echo.py" "${RX_L2_IP4}" > "${udp_log}" 2>&1 &
udp_pid=$!
echo "${udp_pid}" > "${AUX_PID_FILE}"
for _ in $(seq 1 50); do
    if grep -q '^ready$' "${udp_log}" 2>/dev/null; then break; fi
    sleep 0.1
done
if ! grep -q '^ready$' "${udp_log}" 2>/dev/null; then
    print_error "UDP helper did not become ready (log: ${udp_log})"
    cat "${udp_log}"
    exit 1
fi

dut_in_mac="$(ip netns exec "${NS_DUT}" cat "/sys/class/net/${VETH_DUT}/address")"
report_l2="${XDPERF_EXAMPLE_RUNDIR}/nk-l2-mixed.csv"
cfg_l2="$(python3 "${TCP_PY_DIR}/config.py" mixed "${TX_IP4}" "${RX_L2_IP4}" "${dut_in_mac}" 65536 262144 "${DST_PORT}")"
if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --send --recv --device "${VETH_TX}" \
    --plugin mixed.go --plugin-path "${PLUGIN_PATH}" --plugin-config "${cfg_l2}" \
    --tcp-flow-report "${report_l2}" --count 100000 --pps 2000 --parallelism 1 > "${TX_LOG}" 2>&1; then
    print_error "FAIL: netkit L2 mixed run failed (log: ${TX_LOG})"
    tail -n 25 "${TX_LOG}"
    exit 1
fi
sleep 0.2
kill -TERM "${udp_pid}" 2>/dev/null || true
wait "${udp_pid}" 2>/dev/null || true
rm -f "${AUX_PID_FILE}"
stop_pidfile "${SINK_PID_FILE}" xdperf-sink

python3 "${TCP_PY_DIR}/verify.py" mixed "${report_l2}" "${SINK_LOG}" "${TX_LOG}" "${udp_log}" finite
print_success "Case 3 PASS: mixed UDP + TCP flows verified into netkit L2 Pod"

# 4. TCP stream into netkit L3 Pod via TCX + netkit_peer BPF redirect fastpath
# Disable standard IPv4 forwarding on the DUT after neighbor resolution so the
# test only passes when both BPF redirects (bpf_redirect_peer and
# bpf_redirect_neigh) actively forward the packets.
print_info "Case 4 (netkit L3 BPF fastpath): ${FLOWS} TCP flows x ${BYTES} bytes via bpf_redirect_peer + bpf_redirect_neigh (ip_forward=0)"
ip netns exec "${NS_TX}" ping -c 1 -W 1 "${RX_L3_IP4}" >/dev/null
ip netns exec "${NS_DUT}" sysctl -qw net.ipv4.ip_forward=0
start_dut_helper -netkit-fastpath "${VETH_DUT}:${NK_DUT_L3}:${RX_L3_IP4}"
start_nk_sink "${NS_RX_L3}" "${RX_L3_IP4}:${DST_PORT}"
report_fp="${XDPERF_EXAMPLE_RUNDIR}/nk-l3-fastpath-flows.csv"
if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
    --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" --plugin-config "${cfg_l3}" \
    --parallelism "${PARALLELISM}" --tcp-flow-report "${report_fp}" > "${TX_LOG}" 2>&1; then
    print_error "FAIL: netkit L3 BPF fastpath TCP run failed (log: ${TX_LOG})"
    tail -n 25 "${TX_LOG}"
    exit 1
fi
stop_pidfile "${SINK_PID_FILE}" xdperf-sink
ip netns exec "${NS_DUT}" sysctl -qw net.ipv4.ip_forward=1

verify_tcp_flows "${report_fp}" "${SINK_LOG}" "${FLOWS}" "${expected_bytes}"
print_success "Case 4 PASS: ${FLOWS} TCP flows (${expected_bytes} bytes) verified via netkit L3 BPF fastpath"
