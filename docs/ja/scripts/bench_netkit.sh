#!/bin/bash
# docs/ja/scripts/bench_netkit.sh
# Benchmark comparing veth, netkit (L2/L3), and netkit + BPF redirect fastpath
# using xdperf (TCP stream, CPS, and UDP+TCP mixed workloads).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
XDPERF_BIN="${XDPERF_BIN:-${REPO_ROOT}/out/bin/xdperf}"
SINK_BIN="${SINK_BIN:-${REPO_ROOT}/out/bin/xdperf-sink}"
PLUGIN_PATH="${PLUGIN_PATH:-${REPO_ROOT}/out/bin}"
TCP_PY_DIR="${REPO_ROOT}/examples/common/py"
DURATION="${DURATION:-3s}"
MODES="${MODES:-veth netkit-l2 netkit-l3 netkit-bpf}"

if [[ $EUID -ne 0 ]]; then
    echo "Error: must be run as root (sudo)" >&2
    exit 1
fi

cleanup() {
    ip netns del b-tx 2>/dev/null || true
    ip netns del b-dut 2>/dev/null || true
    ip netns del b-rx 2>/dev/null || true
    rm -f /tmp/nkbench-*.log /tmp/nkbench-*.csv /tmp/nkbench-*.json
}
trap cleanup EXIT

softnet_processed() {
    awk '{ sum += strtonum("0x" $1) } END { print sum }' /proc/net/softnet_stat
}

setup_mode() {
    local mode="$1"
    cleanup
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
    elif [ "$mode" = "netkit-l3" ] || [ "$mode" = "netkit-bpf" ]; then
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
        fi
    fi

    ip netns exec b-dut sysctl -qw net.ipv4.ip_forward=1
    ip netns exec b-dut "${SINK_BIN}" -proto udp -listen 127.0.0.1:1 -interval 0 -xdp-pass-dev vdut $fp_arg >/tmp/nkbench-pass.log 2>&1 &
    PASS_PID=$!
    ip netns exec b-rx "${SINK_BIN}" -listen 10.200.2.2:5201 -interval 0 >/tmp/nkbench-sink.log 2>&1 &
    SINK_PID=$!
    sleep 0.3
    ip netns exec b-tx ping -c 1 -W 1 10.200.2.2 >/dev/null
}

teardown_mode() {
    kill -INT "${SINK_PID:-}" "${PASS_PID:-}" 2>/dev/null || true
    wait "${SINK_PID:-}" 2>/dev/null || true
    cleanup
}

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
            >/tmp/nkbench-tx.log 2>&1
        s_after="$(softnet_processed)"
        s_delta=$(( s_after - s_before ))
        python3 - "$mode" "$workers" "$flows" "$ip_id" "$s_delta" /tmp/nkbench-tx.log <<'PY'
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
        --cfg '{"dst_ip":"10.200.2.2","tcp_port":5201,"flows":64,"bytes":"1024","connections":0,"window_segs":4,"port_quarantine_ms":1000}' \
        >/tmp/nkbench-tx.log 2>&1
    s_after="$(softnet_processed)"
    s_delta=$(( s_after - s_before ))
    python3 - "$mode" "1" "$s_delta" /tmp/nkbench-tx.log <<'PY'
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
