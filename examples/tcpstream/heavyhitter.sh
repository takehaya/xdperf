#!/bin/bash
# Static Wasm TCP scenario; use setup.sh first and teardown.sh afterwards.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"

rc=0
scenario_preflight || rc=$?
[ "$rc" -eq 2 ] && exit "$SKIP_EXIT_CODE"
[ "$rc" -ne 0 ] && exit 1
[ -f "${PLUGIN_PATH}/heavyhitter.go.wasm" ] || { print_error 'Build heavyhitter.go first'; exit 1; }
command -v python3 >/dev/null

cleanup() {
    del_loss "${NS_RX}" "${VETH_RX}"
    stop_sink
    stop_xdp_server
}
trap cleanup EXIT

for case_name in ${HH_CASES:-linux4 xdp4 mixed4}; do
    address="${RX_IP4}"
    vlan_args=()
    run_args=(--duration 60s)
    small_bytes=65536
    large_bytes=67108864
    case "$case_name" in
        linux4|xdp4|loss4) ;;
        mixed4) small_bytes=65537; large_bytes=0; run_args=(--duration 5s --pps 10000) ;;
        linux6|xdp6) address="${RX_IP6}" ;;
        linux4vlan|xdp4vlan) address="${RX_VIP4}"; vlan_args=(--tcp-vlan-id "${VLAN_ID}") ;;
        linux6vlan|xdp6vlan) address="${RX_VIP6}"; vlan_args=(--tcp-vlan-id "${VLAN_ID}" --tcp-vlan-pcp 3) ;;
        *) print_error "unknown heavy hitter case: $case_name"; exit 1 ;;
    esac
    listen="${address}:${DST_PORT}"
    [[ "$address" == *:* ]] && listen="[${address}]:${DST_PORT}"
    if [[ "$case_name" == xdp* ]]; then
        start_xdp_server "$listen" "${vlan_args[@]}"
    else
        start_sink "$listen"
    fi
    [ "$case_name" != loss4 ] || add_loss "${NS_RX}" "${VETH_RX}"
    report="${XDPERF_EXAMPLE_RUNDIR}/heavyhitter-${case_name}.csv"
    TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/heavyhitter-${case_name}.log"
    config="$(python3 -c 'import json,sys; print(json.dumps({"address":sys.argv[1],"port":int(sys.argv[2]),"small_bytes":sys.argv[3],"large_bytes":sys.argv[4]}))' "$address" "$DST_PORT" "$small_bytes" "$large_bytes")"
    print_info "heavy hitter ${case_name}: 3 x ${small_bytes} + ${large_bytes} bytes (0 = unlimited)"
    if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --tcp --device "${VETH_TX}" \
        --plugin heavyhitter.go --plugin-path "${PLUGIN_PATH}" --plugin-config "$config" \
        --tcp-mss 1024 --tcp-window 8 --parallelism 1 "${run_args[@]}" \
        --tcp-flow-report "$report" "${vlan_args[@]}" > "$TX_LOG" 2>&1; then
        tail -n 25 "$TX_LOG"
        exit 1
    fi
    del_loss "${NS_RX}" "${VETH_RX}"
    if [[ "$case_name" == xdp* ]]; then
        stop_xdp_server
        received="$(srv_field bytes)"
        accepted="$(srv_field accepted)"
        closed="$(srv_field closed)"
    else
        stop_sink
        received="$(sink_field bytes)"
        accepted="$(sink_field accepted)"
        closed="$(sink_field closed)"
    fi
    [ "$accepted" = 4 ] && [ "$closed" = 4 ] || {
        print_error "receiver bytes=$received accepted=$accepted closed=$closed"; exit 1;
    }
    [ "$(tx_field done)" = 4 ] && [ "$(tx_field failed)" = 0 ] || {
        print_error "sender did not finish all four flows without failures"; exit 1;
    }
    python3 - "$report" "$case_name" "$received" <<'PY'
import csv
import sys
with open(sys.argv[1], newline='') as f:
    rows = list(csv.DictReader(f))
assert len(rows) == 4, rows
mixed = sys.argv[2] == 'mixed4'
targets = [65537] * 3 + [0] if mixed else [65536] * 3 + [67108864]
for i, (row, expected) in enumerate(zip(rows, targets)):
    assert int(row['flow']) == i and int(row['src_port']) == 10000 + i, row
    assert row['state'] == 'done', row
    if expected == 0:
        assert int(row['bytes_acked']) > 0, row
    else:
        assert int(row['bytes_acked']) == expected, row
    if not mixed:
        assert int(row['tx_data']) == expected // 1024, row
assert sum(int(row['bytes_acked']) for row in rows) == int(sys.argv[3]), rows
if sys.argv[2] == 'loss4':
    assert sum(int(row['tx_rtx']) for row in rows) > 0, rows
print('  bytes_acked:', [int(row['bytes_acked']) for row in rows])
print('  tx_data:    ', [int(row['tx_data']) for row in rows])
print('  tx_rtx:     ', [int(row['tx_rtx']) for row in rows])
PY
    print_success "heavy hitter ${case_name}: PASS (receiver bytes=${received}, CSV=${report})"
done
