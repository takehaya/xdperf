#!/bin/bash
# Self-contained UDP + TCP heavy-hitter E2E with independent receive counters.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NS_TX=xdperf-mixed-tx NS_RX=xdperf-mixed-rx VETH_TX=mixed-tx VETH_RX=mixed-rx
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"
check_root
check_xdperf_built
UDP_PID=""
cleanup() {
    if [ -n "$UDP_PID" ]; then kill -TERM "$UDP_PID" 2>/dev/null || true; wait "$UDP_PID" || true; fi
    teardown_tcp_topology
}
trap cleanup EXIT
setup_tcp_topology
for mode in ${MIXED_CASES:-finite duration}; do
for workers in ${MIXED_WORKERS:-1 2}; do
    small_bytes=65536
    large_bytes=262144
    run_args=(--count 128)
    if [ "$mode" = duration ]; then
        small_bytes=4097
        large_bytes=0
        run_args=(--duration 3s)
    fi
    start_sink "${RX_IP4}:${DST_PORT}"
    udp_log="${XDPERF_EXAMPLE_RUNDIR}/mixed-udp-${mode}-${workers}.json"
    ip netns exec "$NS_RX" python3 -u - "$RX_IP4" > "$udp_log" <<'PY' &
import json, signal, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 5353))
s.settimeout(.1)
running, count = True, 0
def stop(*_):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
print('ready', flush=True)
while running:
    try:
        data, peer = s.recvfrom(65535)
        assert data[:4] == bytes.fromhex('12340100') and data[12:20] == b'\x07example', data
        count += 1
        s.sendto(data, peer)
    except socket.timeout:
        pass
print(json.dumps({'udp_packets': count}))
PY
    UDP_PID=$!
    for _ in $(seq 1 50); do
        if grep -q ready "$udp_log"; then break; fi
        sleep .1
    done
    grep -q ready "$udp_log"
    mac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
    report="${XDPERF_EXAMPLE_RUNDIR}/mixed-${mode}-${workers}.csv"
    TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/mixed-${mode}-${workers}.log"
    config="$(python3 -c 'import json,sys; print(json.dumps(dict(src_ip=sys.argv[1],dst_ip=sys.argv[2],dst_mac=sys.argv[3],small_bytes=sys.argv[4],large_bytes=sys.argv[5],tcp_port=int(sys.argv[6]))))' "$TX_IP4" "$RX_IP4" "$mac" "$small_bytes" "$large_bytes" "$DST_PORT")"
    if ! ip netns exec "$NS_TX" "$XDPERF_BIN" run --send --recv --device "$VETH_TX" \
        --plugin mixed.go --plugin-path "$PLUGIN_PATH" --plugin-config "$config" \
        "${run_args[@]}" --pps 2000 --parallelism "$workers" --tcp-mss 1024 --tcp-window 8 \
        --tcp-flow-report "$report" > "$TX_LOG" 2>&1; then
        tail -n 30 "$TX_LOG"; exit 1
    fi
    sleep .2
    kill -TERM "$UDP_PID"
    wait "$UDP_PID"
    UDP_PID=""
    stop_sink
    python3 - "$report" "$TX_LOG" "$udp_log" "$SINK_LOG" "$mode" <<'PY'
import csv, json, math, sys
rows = list(csv.DictReader(open(sys.argv[1])))
targets = [65536] * 3 + [262144] if sys.argv[5] == "finite" else [4097] * 3 + [0]
assert len(rows) == 4
for i, (row, expected) in enumerate(zip(rows, targets)):
    assert int(row['flow']) == i and row['state'] == 'done', row
    assert int(row['bytes_acked']) == expected if expected else int(row['bytes_acked']) > 0, row
udp = json.loads(open(sys.argv[3]).readlines()[-1])['udp_packets']
sink = json.loads(open(sys.argv[4]).readlines()[-1])
assert sink['accepted'] == sink['closed'] == 4, sink
assert sink['bytes'] == sum(int(row['bytes_acked']) for row in rows), sink
line = next(l for l in open(sys.argv[2]) if 'mixed final statistics' in l)
stats = json.loads(line[line.index('{'):])
assert stats['packet_tx'] == udp > 0, (stats, udp)
assert stats['packet_rx'] == udp, stats
assert stats['tcp_tx'] == sum(int(r['tx_pkts']) for r in rows), stats
assert stats['rx_tuple_mismatch'] == stats['rx_invalid_tcp'] == 0, stats
assert stats['packet_errors'] == stats['dispatch_errors'] == 0, stats
assert stats['drain_opportunities'] > 0, stats
opportunities = stats['tcp_opportunities'] + stats['packet_opportunities']
assert abs(stats['tcp_opportunities'] / opportunities - .25) < .03, stats
assert math.isclose(stats['tcp_tx_ratio'], stats['tcp_tx'] / (stats['tcp_tx'] + udp), abs_tol=1e-6), stats
print('PASS:', stats)
PY
    print_success "mixed ${mode} workers=${workers}: TCP completed, UDP TX/RX and ratio verified"
done
done
