#!/bin/bash
# Shared lifecycle for mixed.go plugin scenarios (meant to be sourced).
# SCRIPT_DIR names the scenario directory, as in the existing scenario helpers.
TCP_SCENARIO="$(basename "${SCRIPT_DIR}")"
case "$TCP_SCENARIO" in
    mixed) TCP_PREFIX=mixed ;;
    tcp-template) TCP_PREFIX=tmpl ;;
    tcp-vxlan) TCP_PREFIX=tvx ;;
    tcp-tunnels) TCP_PREFIX=ttun ;;
    tcp-payload) TCP_PREFIX=payload ;;
    *) echo "Unknown TCP plugin scenario: $TCP_SCENARIO" >&2; exit 1 ;;
esac
export NS_TX="xdperf-${TCP_PREFIX}-tx" NS_RX="xdperf-${TCP_PREFIX}-rx"
export VETH_TX="${TCP_PREFIX}-tx" VETH_RX="${TCP_PREFIX}-rx"
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"
TCP_PY_DIR="${COMMON_DIR}/py"
AUX_PID_FILE="${XDPERF_EXAMPLE_RUNDIR}/${TCP_SCENARIO}-helper.pid"

setup_tcp_plugin_topology() {
    check_root
    stop_tcp_plugin_processes
    setup_tcp_topology
    if [ "$TCP_SCENARIO" = tcp-template ]; then
        # QinQ leaves the outer 802.1ad tag visible to XDP on common veth paths.
        local side ns dev host
        for side in tx rx; do
            if [ "$side" = tx ]; then ns="$NS_TX"; dev="$VETH_TX"; host=1; else ns="$NS_RX"; dev="$VETH_RX"; host=2; fi
            ip -n "$ns" link add link "$dev" name outer type vlan protocol 802.1ad id 120
            ip -n "$ns" link add link outer name inner type vlan id 121
            ip -n "$ns" link set outer up
            ip -n "$ns" link set inner up
            ip -n "$ns" addr add "192.168.112.${host}/24" dev inner
            ip -n "$ns" -6 addr add "fd00:112::${host}/64" dev inner nodad
            ip netns exec "$ns" ethtool -K "$dev" rxvlan off txvlan off >/dev/null 2>&1 || true
        done
    elif [ "$TCP_SCENARIO" = tcp-payload ]; then
        # Kernel replies to variable source IPs must resolve to the sender, too.
        local n
        for n in 11 12 13 14; do
            ip -n "$NS_TX" addr add "192.168.110.${n}/32" dev "$VETH_TX"
            ip -n "$NS_TX" -6 addr add "fd00:110::${n}/128" dev "$VETH_TX" nodad
        done
    fi
}

stop_tcp_helper() {
    local pid
    pid="$(cat "$AUX_PID_FILE" 2>/dev/null)" || return 0
    if pid_is "$pid" python3; then kill -TERM "$pid" 2>/dev/null || true; fi
    stop_pidfile "$AUX_PID_FILE" python3 "TCP example helper"
    wait "$pid" 2>/dev/null || true
}

stop_tcp_plugin_processes() {
    stop_tcp_helper
    stop_sink
}

teardown_tcp_plugin_topology() {
    check_root
    stop_tcp_helper
    teardown_tcp_topology
}

# Usage: start_tcp_helper <log> <python-file> [args...]
start_tcp_helper() {
    local log="$1"
    shift
    stop_tcp_helper
    : > "$log"
    setsid ip netns exec "$NS_RX" python3 "$@" > "$log" 2>&1 &
    TCP_HELPER_PID=$!
    echo "$TCP_HELPER_PID" > "$AUX_PID_FILE"
    local i
    for i in $(seq 1 50); do
        if ! kill -0 "$TCP_HELPER_PID" 2>/dev/null; then break; fi
        if grep -q '^ready$' "$log"; then return 0; fi
        sleep .1
    done
    print_error "TCP helper did not become ready (log: $log)"
    cat "$log"
    return 1
}

prepare_tcp_plugin_test() {
    local rc=0
    scenario_preflight || rc=$?
    [ "$rc" -eq 2 ] && exit "$SKIP_EXIT_CODE"
    [ "$rc" -eq 0 ] || exit 1
    trap stop_tcp_plugin_processes EXIT
}

# Usage: run_tcp_plugin <config-json> <report-csv> [extra xdperf args...]
run_tcp_plugin() {
    local config="$1" report="$2"
    shift 2
    local command=(ip netns exec "$NS_TX" "$XDPERF_BIN")
    if [ "$TCP_SCENARIO" = tcp-tunnels ]; then command=(timeout 60 "${command[@]}"); fi
    if ! "${command[@]}" run --send --device "$VETH_TX" \
        --plugin mixed.go --plugin-path "$PLUGIN_PATH" --plugin-config "$config" \
        --tcp-flow-report "$report" "$@" > "$TX_LOG" 2>&1; then
        tail -n 50 "$TX_LOG"
        return 1
    fi
}
