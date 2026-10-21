#!/bin/bash
# Plugin-provided TCP templates against the Linux TCP stack.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_plugin_scenario.sh"
prepare_tcp_plugin_test
srcmac="$(ip netns exec "$NS_TX" cat "/sys/class/net/${VETH_TX}/address")"
dstmac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
for mode in v4 v6 v4vlan v6vlan v4qinq v6qinq; do
    tags=0
    case "$mode" in
        v4) src="$TX_IP4"; dst="$RX_IP4" ;;
        v6) src="$TX_IP6"; dst="$RX_IP6" ;;
        v4vlan) src="$TX_VIP4"; dst="$RX_VIP4"; tags=1 ;;
        v6vlan) src="$TX_VIP6"; dst="$RX_VIP6"; tags=1 ;;
        v4qinq) src=192.168.112.1; dst=192.168.112.2; tags=2 ;;
        v6qinq) src=fd00:112::1; dst=fd00:112::2; tags=2 ;;
    esac
    endpoint="${dst}:${DST_PORT}"
    if [[ "$dst" == *:* ]]; then endpoint="[${dst}]:${DST_PORT}"; fi
    start_sink "$endpoint"
    config="$(python3 "${TCP_PY_DIR}/config.py" template "$srcmac" "$dstmac" "$src" "$dst" "$tags" "$DST_PORT" "$TX_IP4" "$RX_IP4")"
    report="${XDPERF_EXAMPLE_RUNDIR}/template-${mode}.csv"
    TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/template-${mode}.log"
    run_tcp_plugin "$config" "$report" --count 128 --pps 4000 --parallelism 1
    stop_sink
    python3 "${TCP_PY_DIR}/verify.py" template "$report" "$SINK_LOG"
    print_success "TCP template ${mode}: all flows and bytes verified"
done
