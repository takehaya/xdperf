#!/bin/bash
# tcp-exchange: request/response rounds from tcpflow.go (XDP TCP client) to
# xdperf-sink -respond (kernel TCP), compared on both sides.
#
# Overridable: FLOWS (8), CASES (rounds download until-fin server-close
# duration early-close)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Set before tcp_scenario.sh, which has tcpstream's defaults.
FLOWS="${FLOWS:-8}"
CASES="${CASES:-rounds download until-fin server-close duration early-close}"
source "${SCRIPT_DIR}/common.sh"
REQ=1000
RESP=4000
ROUNDS=10

rc=0
scenario_preflight || rc=$?
[ "$rc" -eq 2 ] && exit "$SKIP_EXIT_CODE"
[ "$rc" -eq 0 ] || exit 1
trap stop_sink EXIT

# send <want-exit> <plugin fields> [xdperf args...]: run tcpflow.go with the
# given extra JSON fields and check its exit status.
send() {
    local want="$1" fields="$2" got=0
    shift 2
    local config="{\"dst_ip\":\"${RX_IP4}\",\"tcp_port\":${DST_PORT},\"flows\":${FLOWS},\"window_segs\":16,${fields}}"
    ip netns exec "${NS_TX}" "${XDPERF_BIN}" run --device "${VETH_TX}" \
        --plugin tcpflow.go --plugin-path "${PLUGIN_PATH}" --plugin-config "$config" \
        --parallelism 1 "$@" < /dev/null > "${TX_LOG}" 2>&1 || got=$?
    if { [ "$want" -eq 0 ] && [ "$got" -ne 0 ]; } || { [ "$want" -ne 0 ] && [ "$got" -eq 0 ]; }; then
        print_error "xdperf exit status ${got}, want $([ "$want" -eq 0 ] && echo 0 || echo non-zero) (log: ${TX_LOG})"
        tail -n 20 "${TX_LOG}"
        return 1
    fi
}

# expect <label> <got> <want>
ok=1
expect() {
    if [ "${2:-}" != "$3" ]; then
        print_error "$1=${2:-unset}, want $3"
        ok=0
    fi
}

report() {
    echo "  sender: done=$(tx_field done) failed=$(tx_field failed) rounds_done=$(tx_field rounds_done)" \
        "response_bytes=$(tx_field response_bytes) short_responses=$(tx_field short_responses)" \
        "peer_closed_early=$(tx_field peer_closed_early)"
    echo "  sink:   accepted=$(sink_field accepted) closed=$(sink_field closed) bytes=$(sink_field bytes)" \
        "responses=$(sink_field responses) response_bytes=$(sink_field response_bytes)"
}

# check_flows <rounds per flow> <request bytes per round> <response bytes per round>
check_flows() {
    local rounds=$(( $1 * FLOWS ))
    expect done "$(tx_field done)" "${FLOWS}"
    expect failed "$(tx_field failed)" 0
    expect rounds_done "$(tx_field rounds_done)" "$rounds"
    expect response_bytes "$(tx_field response_bytes)" $(( rounds * $3 ))
    expect sink.accepted "$(sink_field accepted)" "${FLOWS}"
    expect sink.closed "$(sink_field closed)" "${FLOWS}"
    expect sink.bytes "$(sink_field bytes)" $(( rounds * $2 ))
    expect sink.responses "$(sink_field responses)" "$rounds"
}

run_case() {
    local name="$1"
    ok=1
    print_info "case ${name}"
    case "$name" in
        rounds)
            # Each flow sends REQ bytes, waits for RESP bytes, ROUNDS times, then sends FIN.
            start_sink "${RX_IP4}:${DST_PORT}" -respond "${REQ}:${RESP}"
            send 0 "\"bytes\":\"${REQ}\",\"response_bytes\":\"${RESP}\",\"rounds\":${ROUNDS}"
            stop_sink; report
            check_flows "${ROUNDS}" "${REQ}" "${RESP}"
            ;;
        download)
            # bytes 0 sends no request: the sink writes once on accept.
            start_sink "${RX_IP4}:${DST_PORT}" -respond "0:1000000"
            send 0 "\"bytes\":\"0\",\"response_bytes\":\"1000000\""
            stop_sink; report
            check_flows 1 0 1000000
            ;;
        until-fin)
            # One request; the response is everything up to the sink's FIN.
            start_sink "${RX_IP4}:${DST_PORT}" -respond "${REQ}:65536" -close-after 1
            send 0 "\"bytes\":\"${REQ}\",\"response_until_fin\":true"
            stop_sink; report
            check_flows 1 "${REQ}" 65536
            ;;
        server-close)
            # The sink closes after the last response; the client waits for its FIN.
            start_sink "${RX_IP4}:${DST_PORT}" -respond "${REQ}:${RESP}" -close-after "${ROUNDS}"
            send 0 "\"bytes\":\"${REQ}\",\"response_bytes\":\"${RESP}\",\"rounds\":${ROUNDS},\"close\":\"server\""
            stop_sink; report
            check_flows "${ROUNDS}" "${REQ}" "${RESP}"
            ;;
        duration)
            # rounds 0 repeats until --duration; every round the sink answered is counted.
            start_sink "${RX_IP4}:${DST_PORT}" -respond "${REQ}:${RESP}"
            send 0 "\"bytes\":\"${REQ}\",\"response_bytes\":\"${RESP}\",\"rounds\":0" --duration 3s
            stop_sink; report
            local done_rounds
            done_rounds="$(tx_field rounds_done)"
            expect failed "$(tx_field failed)" 0
            [ "${done_rounds:-0}" -gt $(( FLOWS * ROUNDS )) ] || { print_error "rounds_done=${done_rounds}, want more than $(( FLOWS * ROUNDS ))"; ok=0; }
            expect response_bytes "$(tx_field response_bytes)" $(( ${done_rounds:-0} * RESP ))
            expect sink.responses "$(sink_field responses)" "${done_rounds:-0}"
            ;;
        early-close)
            # The sink closes after 3 of 10 rounds: xdperf counts it and exits non-zero.
            start_sink "${RX_IP4}:${DST_PORT}" -respond "${REQ}:${RESP}" -close-after 3
            send 1 "\"bytes\":\"${REQ}\",\"response_bytes\":\"${RESP}\",\"rounds\":${ROUNDS}"
            stop_sink; report
            expect peer_closed_early "$(tx_field peer_closed_early)" "${FLOWS}"
            expect rounds_done "$(tx_field rounds_done)" $(( 3 * FLOWS ))
            expect sink.responses "$(sink_field responses)" $(( 3 * FLOWS ))
            ;;
        *)
            print_error "unknown case: ${name}"
            return 1
            ;;
    esac
    if [ "$ok" -eq 1 ]; then
        print_success "case ${name}: PASS"
        return 0
    fi
    print_error "case ${name}: FAIL (logs: ${TX_LOG}, ${SINK_LOG})"
    return 1
}

failed=0
for c in ${CASES}; do
    run_case "$c" || failed=1
done
exit "$failed"
