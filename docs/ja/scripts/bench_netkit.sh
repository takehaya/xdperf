#!/bin/bash
# docs/ja/scripts/bench_netkit.sh
# Benchmark comparing veth, netkit (L2/L3), and netkit + BPF redirect fastpath
# using xdperf (TCP stream, CPS, and UDP+TCP mixed workloads).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
XDPERF_BIN="${XDPERF_BIN:-${REPO_ROOT}/out/bin/xdperf}"
SINK_BIN="${SINK_BIN:-${REPO_ROOT}/out/bin/xdperf-sink}"
PLUGIN_PATH="${PLUGIN_PATH:-${REPO_ROOT}/out/bin}"
DURATION="${DURATION:-3s}"
MODES="${MODES:-veth netkit-l2 netkit-l3 netkit-bpf}"
SECTIONS="${SECTIONS:-E1 E2}"

if [[ $EUID -ne 0 ]]; then
    echo "Error: must be run as root (sudo)" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d /run/xdperf-nkbench.XXXXXX)"
SINK_PID=""
PASS_PID=""

cleanup_mode() {
    if [ -n "${SINK_PID}" ]; then
        kill -INT "${SINK_PID}" 2>/dev/null || true
        wait "${SINK_PID}" 2>/dev/null || true
        SINK_PID=""
    fi
    if [ -n "${PASS_PID}" ]; then
        kill -INT "${PASS_PID}" 2>/dev/null || true
        wait "${PASS_PID}" 2>/dev/null || true
        PASS_PID=""
    fi
    ip netns del b-tx 2>/dev/null || true
    ip netns del b-dut 2>/dev/null || true
    ip netns del b-rx 2>/dev/null || true
    rm -f "${WORK_DIR}"/*.log "${WORK_DIR}"/*.csv "${WORK_DIR}"/*.json
}

cleanup_all() {
    cleanup_mode
    rm -rf "${WORK_DIR}"
}
trap cleanup_all EXIT

softnet_processed() {
    python3 -c '
with open("/proc/net/softnet_stat") as f:
    print(sum(int(line.split()[0], 16) for line in f if line.strip()))
'
}

wait_sink_ready() {
    local pid="$1" log="$2" label="$3"
    local i
    for i in $(seq 1 50); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "Error: ${label} exited early:" >&2
            cat "${log}" >&2 || true
            return 1
        fi
        if grep -q "listening" "${log}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "Error: ${label} did not become ready within 5s:" >&2
    cat "${log}" >&2 || true
    return 1
}

setup_mode() {
    local mode="$1"
    cleanup_mode
    ip netns add b-tx
    ip netns add b-dut
    ip netns add b-rx
    ip -n b-tx link set lo up
    ip -n b-dut link set lo up
    ip -n b-rx link set lo up

    ip -n b-tx link add vtx numtxqueues 8 numrxqueues 8 type veth peer name vdut numtxqueues 8 numrxqueues 8 netns b-dut
    ip netns exec b-tx sysctl -qw net.ipv6.conf.vtx.disable_ipv6=1
    ip netns exec b-dut sysctl -qw net.ipv6.conf.vdut.disable_ipv6=1
    ip -n b-tx addr add 10.200.1.1/24 dev vtx
    ip -n b-tx link set vtx up
    ip -n b-dut addr add 10.200.1.2/24 dev vdut
    ip -n b-dut link set vdut up
    ip -n b-tx route add 10.200.2.0/24 via 10.200.1.2

    local fp_arg=""
    if [ "$mode" = "veth" ]; then
        ip -n b-dut link add edut numtxqueues 8 numrxqueues 8 type veth peer name erx numtxqueues 8 numrxqueues 8 netns b-rx
        ip netns exec b-dut sysctl -qw net.ipv6.conf.edut.disable_ipv6=1
        ip netns exec b-rx sysctl -qw net.ipv6.conf.erx.disable_ipv6=1
        ip -n b-dut addr add 10.200.2.1/24 dev edut
        ip -n b-dut link set edut up
        ip -n b-rx addr add 10.200.2.2/24 dev erx
        ip -n b-rx link set erx up
        ip -n b-rx route add 10.200.1.0/24 via 10.200.2.1
    elif [ "$mode" = "netkit-l2" ]; then
        ip -n b-dut link add edut type netkit mode l2 peer erx netns b-rx
        ip netns exec b-dut sysctl -qw net.ipv6.conf.edut.disable_ipv6=1
        ip netns exec b-rx sysctl -qw net.ipv6.conf.erx.disable_ipv6=1
        ip -n b-dut addr add 10.200.2.1/24 dev edut
        ip -n b-dut link set edut up
        ip -n b-rx addr add 10.200.2.2/24 dev erx
        ip -n b-rx link set erx up
        ip -n b-rx route add 10.200.1.0/24 via 10.200.2.1
    elif [ "$mode" = "netkit-l3" ] || [ "$mode" = "netkit-bpf" ] || [ "$mode" = "netkit-bpf+flow5" ]; then
        ip -n b-dut link add edut type netkit mode l3 peer erx netns b-rx
        ip netns exec b-dut sysctl -qw net.ipv6.conf.edut.disable_ipv6=1
        ip netns exec b-rx sysctl -qw net.ipv6.conf.erx.disable_ipv6=1
        ip -n b-dut link set edut up
        ip -n b-dut route add 10.200.2.2/32 dev edut
        ip -n b-rx addr add 10.200.2.2/32 dev erx
        ip -n b-rx link set erx up
        ip -n b-rx route add default dev erx
        if [ "$mode" = "netkit-bpf" ]; then
            fp_arg="-netkit-fastpath vdut:edut:10.200.2.2"
        elif [ "$mode" = "netkit-bpf+flow5" ]; then
            fp_arg="-netkit-fastpath vdut:edut:10.200.2.2 -netkit-flow-dump ${WORK_DIR}/flow5.json"
        fi
    fi

    ip netns exec b-dut sysctl -qw net.ipv4.ip_forward=1
    ip netns exec b-rx sysctl -qw net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=4096
    : > "${WORK_DIR}/pass.log"
    : > "${WORK_DIR}/sink.log"
    ip netns exec b-dut "${SINK_BIN}" -proto udp -listen 127.0.0.1:1 -interval 0 -xdp-pass-dev vdut $fp_arg >"${WORK_DIR}/pass.log" 2>&1 &
    PASS_PID=$!
    ip netns exec b-rx "${SINK_BIN}" -proto both -listen 10.200.2.2:5201 -interval 0 >"${WORK_DIR}/sink.log" 2>&1 &
    SINK_PID=$!
    wait_sink_ready "${PASS_PID}" "${WORK_DIR}/pass.log" "DUT helper"
    wait_sink_ready "${SINK_PID}" "${WORK_DIR}/sink.log" "RX sink"
    ip netns exec b-tx ping -c 1 -W 1 10.200.2.2 >/dev/null
}

teardown_mode() {
    cleanup_mode
}

if [[ " ${SECTIONS} " == *" E1 "* ]]; then
echo "=== E1-A: Sustained TCP Stream (${DURATION}) ==="
printf "%-12s | %-6s | %-5s | %-6s | %-10s | %-12s | %-6s | %-12s\n" \
    "Mode" "Worker" "Flows" "IP_ID" "Goodput" "Data Segs/s" "RTX" "Softnet/seg"
for mode in $MODES; do
    for cfg_item in "1:16:8:flow" "1:16:8:shared" "4:64:6:flow"; do
        IFS=":" read -r workers flows win ip_id <<< "$cfg_item"
        setup_mode "$mode"
        s_before="$(softnet_processed)"
        ip netns exec b-tx "${XDPERF_BIN}" run --device vtx \
            --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" \
            --parallelism "$workers" --duration "${DURATION}" \
            --cfg "{\"dst_ip\":\"10.200.2.2\",\"tcp_port\":5201,\"flows\":${flows},\"bytes\":\"0\",\"window_segs\":${win},\"ip_id\":\"${ip_id}\"}" \
            >"${WORK_DIR}/tx.log" 2>&1
        s_after="$(softnet_processed)"
        s_delta=$(( s_after - s_before ))
        python3 - "$mode" "$workers" "$flows" "$ip_id" "$s_delta" "${WORK_DIR}/tx.log" <<'PY'
import json, sys
mode, workers, flows, ip_id, s_delta, tx_log = sys.argv[1:]
s_delta = int(s_delta)
with open(tx_log) as f:
    lines = f.readlines()
stats = json.loads(next(l[l.index("{"):] for l in lines if "tcp final statistics" in l))
rates = json.loads(next(l[l.index("{"):] for l in lines if "tcp connection rates" in l))
sec = rates["load_seconds"]
gbps = stats["bytes_acked"] * 8 / sec / 1e9
segs_s = stats["data_segments"] / sec
rtx = stats["retransmits"]
per_seg = s_delta / max(1, stats["data_segments"])
print(f"{mode:12s} | {workers:6s} | {flows:5s} | {ip_id:6s} | {gbps:6.3f} Gbps | {segs_s:10.0f}/s | {rtx:6d} | {per_seg:10.2f}")
PY
        teardown_mode
    done
done

echo ""
echo "=== E1-B: Short-lived TCP Connection Rate / CPS (${DURATION}, 1 KiB/conn) ==="
printf "%-12s | %-6s | %-12s | %-12s | %-6s | %-12s\n" \
    "Mode" "Worker" "Done CPS" "Completed" "RTX" "Softnet/conn"
for mode in $MODES; do
    setup_mode "$mode"
    s_before="$(softnet_processed)"
    ip netns exec b-tx "${XDPERF_BIN}" run --device vtx \
        --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" \
        --parallelism 1 --duration "${DURATION}" \
        --cfg '{"dst_ip":"10.200.2.2","tcp_port":5201,"flows":64,"bytes":"1024","connections":0,"window_segs":4,"port_reuse_delay_ms":1000}' \
        >"${WORK_DIR}/tx.log" 2>&1
    s_after="$(softnet_processed)"
    s_delta=$(( s_after - s_before ))
    python3 - "$mode" "1" "$s_delta" "${WORK_DIR}/tx.log" <<'PY'
import json, sys
mode, workers, s_delta, tx_log = sys.argv[1:]
s_delta = int(s_delta)
with open(tx_log) as f:
    lines = f.readlines()
stats = json.loads(next(l[l.index("{"):] for l in lines if "tcp final statistics" in l))
rates = json.loads(next(l[l.index("{"):] for l in lines if "tcp connection rates" in l))
cps = rates["done_cps"]
done = stats["done"]
rtx = stats["retransmits"]
per_conn = s_delta / max(1, done)
print(f"{mode:12s} | {workers:6s} | {cps:10.1f}/s | {done:12d} | {rtx:6d} | {per_conn:10.2f}")
PY
    teardown_mode
done

echo ""
echo "=== E1-C: Mixed High-PPS UDP Flood (75%) + 4 TCP Streams (25%) ==="
printf "%-12s | %-9s | %-10s | %-6s | %-12s | %-12s | %-12s\n" \
    "Mode" "TCP Time" "TCP Goodput" "RTX" "UDP TX" "UDP RX" "Softnet/pkt"
for mode in $MODES; do
    setup_mode "$mode"
    dut_mac="$(ip netns exec b-dut cat /sys/class/net/vdut/address)"
    mixed_cfg="{\"src_ip\":\"10.200.1.1\",\"dst_ip\":\"10.200.2.2\",\"dst_mac\":\"${dut_mac}\",\"tcp_port\":5201,\"udp_port\":5201,\"small_bytes\":\"1048576\",\"large_bytes\":\"16777216\",\"packet_weight\":3,\"tcp_weight\":1,\"window_segs\":8,\"mss\":1448}"
    s_before="$(softnet_processed)"
    ip netns exec b-tx "${XDPERF_BIN}" run --send --device vtx \
        --plugin mixed.go --plugin-path "${PLUGIN_PATH}" --plugin-config "${mixed_cfg}" \
        --tcp-flow-report "${WORK_DIR}/flows.csv" --count 2000000 --parallelism 1 \
        >"${WORK_DIR}/tx.log" 2>&1
    s_after="$(softnet_processed)"
    s_delta=$(( s_after - s_before ))
    kill -INT "${SINK_PID}" 2>/dev/null || true
    wait "${SINK_PID}" 2>/dev/null || true
    SINK_PID=""
    python3 - "$mode" "$s_delta" "${WORK_DIR}/tx.log" "${WORK_DIR}/sink.log" <<'PY'
import json, sys
mode, s_delta, tx_log, sink_log = sys.argv[1:]
s_delta = int(s_delta)
with open(tx_log) as f:
    lines = f.readlines()
tstats = json.loads(next(l[l.index("{"):] for l in lines if "tcp final statistics" in l))
mstats = json.loads(next(l[l.index("{"):] for l in lines if "mixed final statistics" in l))
rates = json.loads(next(l[l.index("{"):] for l in lines if "tcp connection rates" in l))
with open(sink_log) as f:
    sink = json.loads(f.readlines()[-1])
sec = rates["load_seconds"]
gbps = tstats["bytes_acked"] * 8 / sec / 1e9
rtx = tstats["retransmits"]
udp_tx = mstats["packet_tx"]
udp_rx = sink.get("udp_packets", 0)
total_pkts = udp_tx + mstats["tcp_tx"]
per_pkt = s_delta / max(1, total_pkts)
print(f"{mode:12s} | {sec:8.3f}s | {gbps:6.3f} Gbps | {rtx:6d} | {udp_tx:12d} | {udp_rx:12d} | {per_pkt:10.2f}")
PY
    teardown_mode
done
fi

if [[ " ${SECTIONS} " == *" E2 "* ]]; then
echo ""
echo "=== E2-A: netkit BPF 5-Tuple Flow Counter (LRU_HASH) Overhead (${DURATION}) ==="
printf "%-16s | %-6s | %-5s | %-10s | %-12s | %-6s\n" \
    "Mode" "Worker" "Flows" "Goodput" "Data Segs/s" "RTX"
for cfg_item in "1:16:8" "1:128:1" "4:64:6"; do
    IFS=":" read -r workers flows win <<< "$cfg_item"
    for mode in netkit-bpf netkit-bpf+flow5; do
        setup_mode "$mode"
        ip netns exec b-tx "${XDPERF_BIN}" run --device vtx \
            --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" \
            --parallelism "$workers" --duration "${DURATION}" \
            --cfg "{\"dst_ip\":\"10.200.2.2\",\"tcp_port\":5201,\"flows\":${flows},\"bytes\":\"0\",\"window_segs\":${win},\"ip_id\":\"flow\"}" \
            >"${WORK_DIR}/tx.log" 2>&1
        python3 - "$mode" "$workers" "$flows" "${WORK_DIR}/tx.log" <<'PY'
import json, sys
mode, workers, flows, tx_log = sys.argv[1:]
with open(tx_log) as f:
    lines = f.readlines()
stats = json.loads(next(l[l.index("{"):] for l in lines if "tcp final statistics" in l))
rates = json.loads(next(l[l.index("{"):] for l in lines if "tcp connection rates" in l))
sec = rates["load_seconds"]
gbps = stats["bytes_acked"] * 8 / sec / 1e9
segs_s = stats["data_segments"] / sec
rtx = stats["retransmits"]
print(f"{mode:16s} | {workers:6s} | {flows:5s} | {gbps:6.3f} Gbps | {segs_s:10.0f}/s | {rtx:6d}")
PY
        teardown_mode
    done
done

echo ""
echo "=== E2-B: netkit BPF 5-Tuple Counter vs --tcp-flow-report Ledger Verification ==="
printf "%-24s | %-6s | %-12s | %-12s | %-14s | %-14s\n" \
    "Workload" "Flows" "Fwd Pkts" "Rev Pkts" "Ingress Match" "Egress Match"

# 1. 128 TCP flows (1w) and 256 TCP flows (4w) x 10 segments (14480 B) with window_segs=1
for item in "1:128:TCP 128x10segs (1w)" "4:256:TCP 256x10segs (4w)"; do
    IFS=":" read -r w fl label <<< "$item"
    setup_mode "netkit-bpf+flow5"
    ip netns exec b-tx "${XDPERF_BIN}" run --device vtx \
        --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" \
        --parallelism "$w" --tcp-flow-report "${WORK_DIR}/flows.csv" \
        --cfg "{\"dst_ip\":\"10.200.2.2\",\"tcp_port\":5201,\"flows\":${fl},\"bytes\":\"14480\",\"window_segs\":1,\"ip_id\":\"flow\"}" \
        >"${WORK_DIR}/tx.log" 2>&1
    kill -INT "${PASS_PID}" 2>/dev/null || true
    wait "${PASS_PID}" 2>/dev/null || true
    PASS_PID=""
    python3 - "$label" "${WORK_DIR}/flows.csv" "${WORK_DIR}/flow5.json" "" <<'PY'
import csv, json, sys
label, report_path, dump_path, _ = sys.argv[1:]
rows = list(csv.DictReader(open(report_path, newline='')))
dump = json.load(open(dump_path))
in_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['ingress']}
eg_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['egress']}
in_ok = eg_ok = fwd_sum = rev_sum = 0
for r in rows:
    sp = int(r['src_port'])
    tx_wire = int(r['tx_pkts']) + int(r['rx_replies'])
    rx_pkts = int(r['rx_pkts'])
    fwd_sum += tx_wire
    rev_sum += rx_pkts
    if in_map.get(('10.200.1.1', '10.200.2.2', sp, 5201, 6)) == tx_wire:
        in_ok += 1
    if eg_map.get(('10.200.2.2', '10.200.1.1', 5201, sp, 6)) == rx_pkts:
        eg_ok += 1
n = len(rows)
print(f"{label:24s} | {n:6d} | {fwd_sum:12d} | {rev_sum:12d} | {in_ok:6d}/{n:<6d} | {eg_ok:6d}/{n:<6d}")
assert in_ok == n and eg_ok == n, f"ledger mismatch: in_ok={in_ok}/{n} eg_ok={eg_ok}/{n}"
PY
    teardown_mode
done

# 2. Mixed UDP flood + 4 unequal TCP flows
setup_mode "netkit-bpf+flow5"
dut_mac="$(ip netns exec b-dut cat /sys/class/net/vdut/address)"
mixed_cfg="{\"src_ip\":\"10.200.1.1\",\"dst_ip\":\"10.200.2.2\",\"dst_mac\":\"${dut_mac}\",\"tcp_port\":5201,\"udp_port\":5201,\"small_bytes\":\"262144\",\"large_bytes\":\"1048576\",\"packet_weight\":3,\"tcp_weight\":1,\"window_segs\":8,\"mss\":1448}"
ip netns exec b-tx "${XDPERF_BIN}" run --send --device vtx \
    --plugin mixed.go --plugin-path "${PLUGIN_PATH}" --plugin-config "${mixed_cfg}" \
    --tcp-flow-report "${WORK_DIR}/flows.csv" --count 500000 --parallelism 1 \
    >"${WORK_DIR}/tx.log" 2>&1
kill -INT "${PASS_PID}" 2>/dev/null || true
wait "${PASS_PID}" 2>/dev/null || true
PASS_PID=""
python3 - "Mixed 1xUDP + 4xTCP" "${WORK_DIR}/flows.csv" "${WORK_DIR}/flow5.json" "${WORK_DIR}/tx.log" <<'PY'
import csv, json, sys
label, report_path, dump_path, tx_log = sys.argv[1:]
rows = list(csv.DictReader(open(report_path, newline='')))
dump = json.load(open(dump_path))
with open(tx_log) as f:
    lines = f.readlines()
mstats = json.loads(next(l[l.index("{"):] for l in lines if "mixed final statistics" in l))
in_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['ingress']}
eg_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['egress']}
in_ok = eg_ok = fwd_sum = rev_sum = 0
udp_tx = int(mstats['packet_tx'])
fwd_sum += udp_tx
if in_map.get(('10.200.1.1', '10.200.2.2', 53000, 5201, 17)) == udp_tx:
    in_ok += 1
for r in rows:
    sp = int(r['src_port'])
    tx_wire = int(r['tx_pkts']) + int(r['rx_replies'])
    rx_pkts = int(r['rx_pkts'])
    fwd_sum += tx_wire
    rev_sum += rx_pkts
    if in_map.get(('10.200.1.1', '10.200.2.2', sp, 5201, 6)) == tx_wire:
        in_ok += 1
    if eg_map.get(('10.200.2.2', '10.200.1.1', 5201, sp, 6)) == rx_pkts:
        eg_ok += 1
n_in = len(rows) + 1
n_eg = len(rows)
print(f"{label:24s} | {n_in:6d} | {fwd_sum:12d} | {rev_sum:12d} | {in_ok:6d}/{n_in:<6d} | {eg_ok:6d}/{n_eg:<6d}")
assert in_ok == n_in and eg_ok == n_eg, f"mixed ledger mismatch: in_ok={in_ok}/{n_in} eg_ok={eg_ok}/{n_eg}"
PY
teardown_mode
fi
