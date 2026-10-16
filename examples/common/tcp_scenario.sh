#!/bin/bash
# examples/common/tcp_scenario.sh
# Shared implementation for the tcpstream scenario (meant to be sourced)
#
# Topology: two netns connected by a veth pair. The sender runs
# `xdperf run --tcp` (an XDP-implemented TCP client: SYN / data / FIN all
# from XDP, see docs/ja/design_xdp_tcp.md); the receiver is either
# xdperf-sink (a plain kernel-TCP sink that counts connections and bytes) or
# `xdperf run --tcp-server` (the XDP responder, design doc section 12). The
# "linux*" cases go the other way round: a kernel TCP client (socat) streams
# into the XDP responder. Each side also gets a VLAN sub-interface so the
# tagged path can be exercised.
#
# Overridable via environment variables:
#   FLOWS (16) / BYTES (1m) / WINDOW (16) / PARALLELISM (1) / DST_PORT (5201)
#   CASES — which cases to run (default: all of the below)
#     v4 v6 v4vlan v6vlan          --tcp client -> xdperf-sink (kernel TCP)
#     v4srv v6srv v4vlansrv v6vlansrv v4ack2srv
#                                  --tcp client -> --tcp-server (XDP responder)
#     linux4 linux6                socat (kernel TCP) -> --tcp-server
#     v4loss                       --tcp client -> xdperf-sink with ~1% loss each way
#     linux4loss                   socat -> --tcp-server with ~1% loss each way
#   LOSS_PCT (1) — loss for the *loss cases

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${COMMON_DIR}/test_utils.sh"
source "${COMMON_DIR}/netns.sh"
source "${COMMON_DIR}/veth.sh"

NS_TX="${NS_TX:-xdperf-tcp-tx}"
NS_RX="${NS_RX:-xdperf-tcp-rx}"
VETH_TX="${VETH_TX:-tcp-tx}"
VETH_RX="${VETH_RX:-tcp-rx}"
VLAN_ID="${VLAN_ID:-110}"
TX_IP4="${TX_IP4:-192.168.110.1}"
RX_IP4="${RX_IP4:-192.168.110.2}"
TX_IP6="${TX_IP6:-fd00:110::1}"
RX_IP6="${RX_IP6:-fd00:110::2}"
TX_VIP4="${TX_VIP4:-192.168.111.1}"
RX_VIP4="${RX_VIP4:-192.168.111.2}"
TX_VIP6="${TX_VIP6:-fd00:111::1}"
RX_VIP6="${RX_VIP6:-fd00:111::2}"

FLOWS="${FLOWS:-16}"
BYTES="${BYTES:-1m}"
WINDOW="${WINDOW:-16}"
PARALLELISM="${PARALLELISM:-1}"
DST_PORT="${DST_PORT:-5201}"
CASES="${CASES:-v4 v6 v4vlan v6vlan v4srv v6srv v4vlansrv v6vlansrv v4ack2srv linux4 linux6 v4loss linux4loss}"
LOSS_PCT="${LOSS_PCT:-1}"

SINK_BIN="${SINK_BIN:-${REPO_ROOT}/out/bin/xdperf-sink}"
SINK_PID_FILE="${SINK_PID_FILE:-${XDPERF_EXAMPLE_RUNDIR}/tcp-sink.pid}"
SINK_LOG="${SINK_LOG:-${XDPERF_EXAMPLE_RUNDIR}/tcp-sink.log}"
TX_LOG="${TX_LOG:-${XDPERF_EXAMPLE_RUNDIR}/tcp-tx.log}"
SRV_PID_FILE="${SRV_PID_FILE:-${XDPERF_EXAMPLE_RUNDIR}/tcp-srv.pid}"
SRV_LOG="${SRV_LOG:-${XDPERF_EXAMPLE_RUNDIR}/tcp-srv.log}"
PASS_PID_FILE="${PASS_PID_FILE:-${XDPERF_EXAMPLE_RUNDIR}/tcp-pass.pid}"
PASS_LOG="${PASS_LOG:-${XDPERF_EXAMPLE_RUNDIR}/tcp-pass.log}"

SKIP_EXIT_CODE=3

to_number() {
    local v="$1"
    case "$v" in
        *k) echo $(( ${v%k} * 1000 )) ;;
        *m) echo $(( ${v%m} * 1000000 )) ;;
        *g) echo $(( ${v%g} * 1000000000 )) ;;
        *) echo "$v" ;;
    esac
}

setup_tcp_topology() {
    check_root
    create_netns "${NS_TX}"
    create_netns "${NS_RX}"
    create_veth_pair "${VETH_TX}" "${NS_TX}" "${VETH_RX}" "${NS_RX}"
    local ns dev ip4 ip6 vip4 vip6
    for side in tx rx; do
        if [ "$side" = tx ]; then
            ns="${NS_TX}"; dev="${VETH_TX}"; ip4="${TX_IP4}"; ip6="${TX_IP6}"; vip4="${TX_VIP4}"; vip6="${TX_VIP6}"
        else
            ns="${NS_RX}"; dev="${VETH_RX}"; ip4="${RX_IP4}"; ip6="${RX_IP6}"; vip4="${RX_VIP4}"; vip6="${RX_VIP6}"
        fi
        ip netns exec "$ns" ip addr add "${ip4}/24" dev "$dev"
        ip netns exec "$ns" ip -6 addr add "${ip6}/64" dev "$dev"
        ip netns exec "$ns" ip link add link "$dev" name "${dev}.${VLAN_ID}" type vlan id "${VLAN_ID}"
        ip netns exec "$ns" ip addr add "${vip4}/24" dev "${dev}.${VLAN_ID}"
        ip netns exec "$ns" ip -6 addr add "${vip6}/64" dev "${dev}.${VLAN_ID}"
        ip netns exec "$ns" ip link set "${dev}.${VLAN_ID}" up
    done
    # Give IPv6 DAD a moment so the addresses are usable as sources
    sleep 2
    print_success "Topology ready: ${NS_TX}(${VETH_TX}) <-> ${NS_RX}(${VETH_RX}), VLAN ${VLAN_ID} on both"
}

teardown_tcp_topology() {
    check_root
    stop_sink
    stop_xdp_server
    stop_pass_prog
    delete_netns "${NS_TX}"
    delete_netns "${NS_RX}"
    print_success "Topology removed"
}

# pid_is <pid> <comm>: true if pid is alive and runs the expected command.
# A stale pid file may name a pid the kernel has since reused for an
# unrelated process; we signal as root, so check before every kill.
pid_is() {
    [ -n "$1" ] && [ "$(cat "/proc/$1/comm" 2>/dev/null)" = "$2" ]
}

kill_stale_sink() {
    local pid
    pid="$(cat "${SINK_PID_FILE}" 2>/dev/null)" || return 0
    if pid_is "$pid" xdperf-sink; then
        kill "$pid" 2>/dev/null || true
        local i
        for i in $(seq 1 20); do
            pid_is "$pid" xdperf-sink || break
            sleep 0.1
        done
    fi
    rm -f "${SINK_PID_FILE}"
}

# Start xdperf-sink in the receive namespace. The pass-through XDP program on
# the receive veth is required on veth: without an XDP program on the peer,
# the kernel does not wake the peer's NAPI for XDP_TX'd frames and the
# sender's last ACK stays queued (see cmd/xdperf-sink/main.go).
# Usage: start_sink <listen-addr>
start_sink() {
    local listen="$1"
    kill_stale_sink
    : > "${SINK_LOG}" # the readiness check must not see the previous case's line
    setsid ip netns exec "${NS_RX}" "${SINK_BIN}" -listen "$listen" -interval 0 -xdp-pass-dev "${VETH_RX}" \
        > "${SINK_LOG}" 2>&1 &
    SINK_PID=$!
    echo "${SINK_PID}" > "${SINK_PID_FILE}"
    local i
    for i in $(seq 1 50); do
        if ! kill -0 "${SINK_PID}" 2>/dev/null; then
            print_error "Failed to start xdperf-sink (log: ${SINK_LOG})"
            cat "${SINK_LOG}" 2>/dev/null
            rm -f "${SINK_PID_FILE}"
            return 1
        fi
        if ip netns exec "${NS_RX}" ip -d link show dev "${VETH_RX}" 2>/dev/null | grep -q "prog/xdp" &&
           grep -q "listening" "${SINK_LOG}" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    print_error "xdperf-sink did not become ready within 5s (log: ${SINK_LOG})"
    kill "${SINK_PID}" 2>/dev/null || true
    rm -f "${SINK_PID_FILE}"
    return 1
}

# Stop the sink with SIGINT so it prints its JSON summary, then wait for it.
stop_sink() {
    local pid="${SINK_PID:-}"
    if [ -z "$pid" ]; then
        pid="$(cat "${SINK_PID_FILE}" 2>/dev/null)" || true
    fi
    if pid_is "$pid" xdperf-sink; then
        kill -INT "$pid" 2>/dev/null || true
        local i
        for i in $(seq 1 50); do
            pid_is "$pid" xdperf-sink || break
            sleep 0.1
        done
    fi
    rm -f "${SINK_PID_FILE}"
    SINK_PID=""
}

# Extract a numeric field from the JSON summary line of the sink log
sink_field() {
    grep '^{' "${SINK_LOG}" | tail -n 1 | grep -o "\"$1\":[0-9]*" | cut -d: -f2
}

# Extract a numeric field from xdperf's "tcp final statistics" log line
tx_field() {
    grep "tcp final statistics" "${TX_LOG}" | tail -n 1 | grep -o "\"$1\": [0-9]*" | awk '{print $2}'
}

# Extract a numeric field from the responder's "tcp server final statistics" log line
srv_field() {
    grep "tcp server final statistics" "${SRV_LOG}" | tail -n 1 | grep -o "\"$1\": [0-9]*" | awk '{print $2}'
}

# Send SIGINT to the process in a pid file (if it is still <comm>) and wait
# for it to exit. Usage: stop_pidfile <file> <comm> <label>
stop_pidfile() {
    local file="$1" comm="$2" label="$3" pid
    pid="$(cat "$file" 2>/dev/null)" || return 0
    if pid_is "$pid" "$comm"; then
        kill -INT "$pid" 2>/dev/null || true
        local i
        for i in $(seq 1 100); do
            pid_is "$pid" "$comm" || break
            sleep 0.1
        done
        if pid_is "$pid" "$comm"; then
            print_error "${label} (pid ${pid}) did not exit after SIGINT; killing it"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$file"
}

# Start the XDP responder (xdperf run --tcp-server) in the receive namespace
# and wait until its program is attached. Loading the BPF objects takes a
# couple of seconds, so callers must not send traffic before this returns.
# Usage: start_xdp_server <listen-addr> [extra xdperf args...]
start_xdp_server() {
    local listen="$1"
    shift
    stop_xdp_server
    # Truncate here, not only in the child's redirect: the readiness check
    # below must not see the previous case's "started" line.
    : > "${SRV_LOG}"
    setsid ip netns exec "${NS_RX}" "${XDPERF_BIN}" run --tcp-server --device "${VETH_RX}" \
        --tcp-listen "$listen" "$@" > "${SRV_LOG}" 2>&1 &
    echo "$!" > "${SRV_PID_FILE}"
    local i
    for i in $(seq 1 150); do
        if grep -q "TCP responder started" "${SRV_LOG}" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$(cat "${SRV_PID_FILE}")" 2>/dev/null; then
            print_error "xdperf --tcp-server exited early (log: ${SRV_LOG})"
            tail -n 5 "${SRV_LOG}"
            rm -f "${SRV_PID_FILE}"
            return 1
        fi
        sleep 0.1
    done
    print_error "xdperf --tcp-server did not become ready within 15s (log: ${SRV_LOG})"
    stop_xdp_server
    return 1
}

# Stop the responder with SIGINT so it logs its final statistics.
stop_xdp_server() {
    stop_pidfile "${SRV_PID_FILE}" xdperf "xdperf --tcp-server"
}

# Attach a pass-through XDP program to the transmit veth (needed when the
# kernel TCP client lives on that side: see the veth NAPI note on start_sink).
# xdperf-sink is only used here as the attacher; its UDP listener is idle.
start_pass_prog() {
    stop_pass_prog
    setsid ip netns exec "${NS_TX}" "${SINK_BIN}" -proto udp -listen 127.0.0.1:1 -interval 0 \
        -xdp-pass-dev "${VETH_TX}" > "${PASS_LOG}" 2>&1 &
    echo "$!" > "${PASS_PID_FILE}"
    local i
    for i in $(seq 1 50); do
        if ip netns exec "${NS_TX}" ip -d link show dev "${VETH_TX}" 2>/dev/null | grep -q "prog/xdp"; then
            return 0
        fi
        sleep 0.1
    done
    print_error "pass-through XDP program did not attach to ${VETH_TX} (log: ${PASS_LOG})"
    stop_pass_prog
    return 1
}

stop_pass_prog() {
    stop_pidfile "${PASS_PID_FILE}" xdperf-sink "xdperf-sink (xdp pass)"
}

scenario_preflight() {
    check_root
    check_xdperf_built
    if [ ! -x "${SINK_BIN}" ]; then
        print_error "xdperf-sink not found: ${SINK_BIN} (run 'make build' at the repo root)"
        return 1
    fi
    if ! ip netns pids "${NS_TX}" >/dev/null 2>&1 || ! ip netns pids "${NS_RX}" >/dev/null 2>&1; then
        print_error "netns not found. Run setup.sh first"
        return 1
    fi
    local lf=0
    check_live_frames "${NS_TX}" "${VETH_TX}" || lf=$?
    if [ "${lf}" -eq 2 ]; then
        print_error "xdperf probe failed on ${VETH_TX} (not a kernel-support SKIP)"
        return 1
    fi
    if [ "${lf}" -eq 1 ]; then
        print_info "SKIP: this kernel does not support XDP live-frames (BPF_PROG_RUN)"
        return 2
    fi
    return 0
}

# Run one case: <name> <sink-listen> <tcp-dst> [extra xdperf args...]
run_tcp_case() {
    local name="$1" listen="$2" dst="$3"
    shift 3
    print_info "case ${name}: ${FLOWS} flows x ${BYTES} bytes -> ${dst}"
    start_sink "$listen" || return 1

    local expected_bytes
    expected_bytes=$(( $(to_number "${BYTES}") * FLOWS ))
    if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --tcp --device "${VETH_TX}" \
        --tcp-dst "$dst" --tcp-flows "${FLOWS}" --tcp-bytes "${BYTES}" \
        --tcp-window "${WINDOW}" --parallelism "${PARALLELISM}" "$@" > "${TX_LOG}" 2>&1; then
        print_error "xdperf --tcp failed (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        stop_sink
        return 1
    fi
    stop_sink

    local tx_done tx_failed tx_acked tx_rtx sink_accepted sink_closed sink_bytes
    tx_done="$(tx_field done)"; tx_failed="$(tx_field failed)"; tx_acked="$(tx_field bytes_acked)"; tx_rtx="$(tx_field retransmits)"
    sink_accepted="$(sink_field accepted)"; sink_closed="$(sink_field closed)"; sink_bytes="$(sink_field bytes)"
    echo "  sender: done=${tx_done} failed=${tx_failed} bytes_acked=${tx_acked} retransmits=${tx_rtx}"
    echo "  sink:   accepted=${sink_accepted} closed=${sink_closed} bytes=${sink_bytes}"

    local ok=1
    [ "${tx_done:-0}" -eq "${FLOWS}" ] || { print_error "sender: done=${tx_done} != ${FLOWS}"; ok=0; }
    [ "${tx_failed:-1}" -eq 0 ] || { print_error "sender: failed=${tx_failed}"; ok=0; }
    [ "${tx_acked:-0}" -eq "${expected_bytes}" ] || { print_error "sender: bytes_acked=${tx_acked} != ${expected_bytes}"; ok=0; }
    [ "${sink_accepted:-0}" -eq "${FLOWS}" ] || { print_error "sink: accepted=${sink_accepted} != ${FLOWS}"; ok=0; }
    [ "${sink_closed:-0}" -eq "${FLOWS}" ] || { print_error "sink: closed=${sink_closed} != ${FLOWS}"; ok=0; }
    [ "${sink_bytes:-0}" -eq "${expected_bytes}" ] || { print_error "sink: bytes=${sink_bytes} != ${expected_bytes}"; ok=0; }
    if [ "$ok" -eq 1 ]; then
        print_success "case ${name}: PASS"
        return 0
    fi
    print_error "case ${name}: FAIL (logs: ${TX_LOG}, ${SINK_LOG})"
    return 1
}

# Run one case against the XDP responder: <name> <listen> <tcp-dst> <server args> [client args...]
# (server args is a single string, split on spaces; "" for none)
run_tcp_server_case() {
    local name="$1" listen="$2" dst="$3" srv_args="$4"
    shift 4
    print_info "case ${name}: ${FLOWS} flows x ${BYTES} bytes -> ${dst} (XDP responder ${srv_args})"
    # shellcheck disable=SC2086
    start_xdp_server "$listen" ${srv_args} || return 1

    local expected_bytes
    expected_bytes=$(( $(to_number "${BYTES}") * FLOWS ))
    if ! ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --tcp --device "${VETH_TX}" \
        --tcp-dst "$dst" --tcp-flows "${FLOWS}" --tcp-bytes "${BYTES}" \
        --tcp-window "${WINDOW}" --parallelism "${PARALLELISM}" "$@" > "${TX_LOG}" 2>&1; then
        print_error "xdperf --tcp failed (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        stop_xdp_server
        return 1
    fi
    sleep 0.5
    stop_xdp_server

    local tx_done tx_failed tx_acked tx_rtx tx_segs srv_accepted srv_closed srv_bytes srv_unexpected srv_badlen
    tx_done="$(tx_field done)"; tx_failed="$(tx_field failed)"; tx_acked="$(tx_field bytes_acked)"; tx_rtx="$(tx_field retransmits)"
    tx_segs="$(tx_field data_segments)"
    srv_accepted="$(srv_field accepted)"; srv_closed="$(srv_field closed)"; srv_bytes="$(srv_field bytes)"; srv_unexpected="$(srv_field unexpected)"
    srv_badlen="$(srv_field bad_length)"
    echo "  sender:    done=${tx_done} failed=${tx_failed} bytes_acked=${tx_acked} retransmits=${tx_rtx}"
    echo "  responder: accepted=${srv_accepted} closed=${srv_closed} bytes=${srv_bytes} unexpected=${srv_unexpected}"

    local ok=1
    [ "${tx_done:-0}" -eq "${FLOWS}" ] || { print_error "sender: done=${tx_done} != ${FLOWS}"; ok=0; }
    [ "${tx_failed:-1}" -eq 0 ] || { print_error "sender: failed=${tx_failed}"; ok=0; }
    [ "${tx_acked:-0}" -eq "${expected_bytes}" ] || { print_error "sender: bytes_acked=${tx_acked} != ${expected_bytes}"; ok=0; }
    [ "${srv_accepted:-0}" -eq "${FLOWS}" ] || { print_error "responder: accepted=${srv_accepted} != ${FLOWS}"; ok=0; }
    [ "${srv_closed:-0}" -eq "${FLOWS}" ] || { print_error "responder: closed=${srv_closed} != ${FLOWS}"; ok=0; }
    [ "${srv_bytes:-0}" -eq "${expected_bytes}" ] || { print_error "responder: bytes=${srv_bytes} != ${expected_bytes}"; ok=0; }
    [ "${srv_unexpected:-1}" -eq 0 ] || { print_error "responder: unexpected=${srv_unexpected}"; ok=0; }
    # truncated frames (IP length beyond the frame) must never reach the responder
    [ "${srv_badlen:-1}" -eq 0 ] || { print_error "responder: bad_length=${srv_badlen}"; ok=0; }
    # No loss is injected here, so retransmissions mean the client and the
    # responder disagree (e.g. a missing PSH leaves the tail of each window
    # unacked until RTO with --tcp-ack-every). Allow 1% for scheduling noise.
    [ $(( ${tx_rtx:-0} * 100 )) -le "${tx_segs:-0}" ] || { print_error "sender: retransmits=${tx_rtx} > 1% of ${tx_segs} segments"; ok=0; }
    if [ "$ok" -eq 1 ]; then
        print_success "case ${name}: PASS"
        return 0
    fi
    print_error "case ${name}: FAIL (logs: ${TX_LOG}, ${SRV_LOG})"
    return 1
}

# Inject ~LOSS_PCT% loss in both directions on one veth end, seen from the
# kernel side of <ns>/<dev>: egress via netem (frames the kernel sends) and
# ingress via a tc gact random drop (frames XDP_PASSes up). XDP_TX and live
# frames bypass the qdisc layer, so loss must be added where the kernel
# stack sends/receives, not on the XDP side.
# Usage: add_loss <ns> <dev> / del_loss <ns> <dev>
add_loss() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" tc qdisc add dev "$dev" root netem loss "${LOSS_PCT}%"
    ip netns exec "$ns" tc qdisc add dev "$dev" clsact
    ip netns exec "$ns" tc filter add dev "$dev" ingress matchall \
        action gact pass random netrand drop $(( 100 / LOSS_PCT ))
}

del_loss() {
    local ns="$1" dev="$2"
    ip netns exec "$ns" tc qdisc del dev "$dev" root 2>/dev/null || true
    ip netns exec "$ns" tc qdisc del dev "$dev" clsact 2>/dev/null || true
}

# Kernel TCP client (socat) -> XDP responder: <name> <listen> <socat target>
# One connection streaming FLOWS*BYTES zero bytes from /dev/zero.
run_linux_client_case() {
    local name="$1" listen="$2" target="$3"
    local expected_bytes
    expected_bytes=$(( $(to_number "${BYTES}") * FLOWS ))
    print_info "case ${name}: socat ${expected_bytes} bytes -> ${target} (XDP responder)"
    if ! command -v socat >/dev/null 2>&1; then
        print_info "SKIP ${name}: socat not installed"
        return 0
    fi
    start_pass_prog || return 1
    if ! start_xdp_server "$listen"; then
        stop_pass_prog
        return 1
    fi
    local rc=0
    ip netns exec "${NS_TX}" bash -c "head -c ${expected_bytes} /dev/zero | socat -u - ${target}" > "${TX_LOG}" 2>&1 || rc=$?
    sleep 0.5
    stop_xdp_server
    stop_pass_prog
    if [ "$rc" -ne 0 ]; then
        print_error "socat failed (rc=${rc}, log: ${TX_LOG})"
        cat "${TX_LOG}"
        return 1
    fi

    local srv_accepted srv_closed srv_bytes srv_unexpected srv_badlen
    srv_accepted="$(srv_field accepted)"; srv_closed="$(srv_field closed)"; srv_bytes="$(srv_field bytes)"; srv_unexpected="$(srv_field unexpected)"
    srv_badlen="$(srv_field bad_length)"
    echo "  responder: accepted=${srv_accepted} closed=${srv_closed} bytes=${srv_bytes} unexpected=${srv_unexpected}"
    local ok=1
    [ "${srv_accepted:-0}" -eq 1 ] || { print_error "responder: accepted=${srv_accepted} != 1"; ok=0; }
    [ "${srv_closed:-0}" -eq 1 ] || { print_error "responder: closed=${srv_closed} != 1"; ok=0; }
    [ "${srv_bytes:-0}" -eq "${expected_bytes}" ] || { print_error "responder: bytes=${srv_bytes} != ${expected_bytes}"; ok=0; }
    [ "${srv_unexpected:-1}" -eq 0 ] || { print_error "responder: unexpected=${srv_unexpected}"; ok=0; }
    # truncated frames (IP length beyond the frame) must never reach the responder
    [ "${srv_badlen:-1}" -eq 0 ] || { print_error "responder: bad_length=${srv_badlen}"; ok=0; }
    if [ "$ok" -eq 1 ]; then
        print_success "case ${name}: PASS"
        return 0
    fi
    print_error "case ${name}: FAIL (logs: ${TX_LOG}, ${SRV_LOG})"
    return 1
}

run_tcp_test() {
    local rc=0
    scenario_preflight || rc=$?
    [ "${rc}" -eq 2 ] && return "${SKIP_EXIT_CODE}"
    [ "${rc}" -ne 0 ] && return 1

    local failed=0 c
    for c in ${CASES}; do
        case "$c" in
            v4) run_tcp_case v4 "${RX_IP4}:${DST_PORT}" "${RX_IP4}:${DST_PORT}" || failed=1 ;;
            v6) run_tcp_case v6 "[${RX_IP6}]:${DST_PORT}" "[${RX_IP6}]:${DST_PORT}" || failed=1 ;;
            v4vlan) run_tcp_case v4vlan "${RX_VIP4}:${DST_PORT}" "${RX_VIP4}:${DST_PORT}" --tcp-vlan-id "${VLAN_ID}" || failed=1 ;;
            v6vlan) run_tcp_case v6vlan "[${RX_VIP6}]:${DST_PORT}" "[${RX_VIP6}]:${DST_PORT}" --tcp-vlan-id "${VLAN_ID}" --tcp-vlan-pcp 3 || failed=1 ;;
            v4srv) run_tcp_server_case v4srv "${RX_IP4}:${DST_PORT}" "${RX_IP4}:${DST_PORT}" "" || failed=1 ;;
            v6srv) run_tcp_server_case v6srv "[${RX_IP6}]:${DST_PORT}" "[${RX_IP6}]:${DST_PORT}" "" || failed=1 ;;
            v4vlansrv) run_tcp_server_case v4vlansrv "${RX_VIP4}:${DST_PORT}" "${RX_VIP4}:${DST_PORT}" "--tcp-vlan-id ${VLAN_ID}" --tcp-vlan-id "${VLAN_ID}" || failed=1 ;;
            v6vlansrv) run_tcp_server_case v6vlansrv "[${RX_VIP6}]:${DST_PORT}" "[${RX_VIP6}]:${DST_PORT}" "--tcp-vlan-id ${VLAN_ID} --tcp-vlan-pcp 3" --tcp-vlan-id "${VLAN_ID}" --tcp-vlan-pcp 3 || failed=1 ;;
            v4ack2srv) run_tcp_server_case v4ack2srv ":${DST_PORT}" "${RX_IP4}:${DST_PORT}" "--tcp-ack-every 2" || failed=1 ;;
            linux4) run_linux_client_case linux4 "${RX_IP4}:${DST_PORT}" "TCP4:${RX_IP4}:${DST_PORT}" || failed=1 ;;
            linux6) run_linux_client_case linux6 "[${RX_IP6}]:${DST_PORT}" "TCP6:[${RX_IP6}]:${DST_PORT}" || failed=1 ;;
            v4loss)
                add_loss "${NS_RX}" "${VETH_RX}"
                run_tcp_case v4loss "${RX_IP4}:${DST_PORT}" "${RX_IP4}:${DST_PORT}" || failed=1
                del_loss "${NS_RX}" "${VETH_RX}" ;;
            linux4loss)
                add_loss "${NS_TX}" "${VETH_TX}"
                run_linux_client_case linux4loss "${RX_IP4}:${DST_PORT}" "TCP4:${RX_IP4}:${DST_PORT}" || failed=1
                del_loss "${NS_TX}" "${VETH_TX}" ;;
            *) print_error "unknown case: $c"; failed=1 ;;
        esac
    done
    [ "$failed" -eq 0 ]
}
