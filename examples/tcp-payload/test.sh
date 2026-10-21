#!/bin/bash
# Optional flow features against Linux TCP, with independent payload checking.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_plugin_scenario.sh"
prepare_tcp_plugin_test
srcmac="$(ip netns exec "$NS_TX" cat "/sys/class/net/${VETH_TX}/address")"
dstmac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
for version in 4 6; do
    src="$TX_IP4"; dst="$RX_IP4"
    if [ "$version" = 6 ]; then src="$TX_IP6"; dst="$RX_IP6"; fi
    for feature in timestamps declined payload variables combined loss; do
        peer_timestamps=1
        if [ "$feature" = declined ]; then peer_timestamps=0; fi
        ip netns exec "$NS_RX" sysctl -qw "net.ipv4.tcp_timestamps=${peer_timestamps}"
        pattern=00
        if [[ "$feature" = payload || "$feature" = combined || "$feature" = loss ]]; then pattern=0123fe; fi
        start_sink 127.0.0.1:5202 # maintain XDP_PASS on the peer veth
        verifylog="${XDPERF_EXAMPLE_RUNDIR}/payload-${version}-${feature}-verify.log"
        start_tcp_helper "$verifylog" "${SCRIPT_DIR}/sink.py" "$dst" "$version" "$pattern"
        config="$(python3 "${TCP_PY_DIR}/config.py" payload "$srcmac" "$dstmac" "$src" "$dst" "$feature" "$pattern" "$TX_IP4" "$RX_IP4")"
        if [ "$feature" = loss ]; then
            # Lose ACKs on the return path; retransmission bytes are also checked.
            ip netns exec "$NS_RX" tc qdisc add dev "$VETH_RX" root netem loss 5%
        fi
        report="${XDPERF_EXAMPLE_RUNDIR}/payload-${version}-${feature}.csv"
        TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/payload-${version}-${feature}.log"
        run_tcp_plugin "$config" "$report" --count 128 --pps 4000 --parallelism 1
        if ! wait "$TCP_HELPER_PID"; then cat "$verifylog"; exit 1; fi
        rm -f "$AUX_PID_FILE"
        if [ "$feature" = loss ]; then ip netns exec "$NS_RX" tc qdisc del dev "$VETH_RX" root; fi
        stop_sink
        python3 "${TCP_PY_DIR}/verify.py" payload "$report" "$TX_LOG"
        print_success "TCP payload IPv${version} ${feature}: four streams and 77830 bytes verified"
    done
done
