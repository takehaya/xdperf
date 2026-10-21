#!/bin/bash
# XDP TCP inside VXLAN, terminated by a Linux vxlan device and kernel TCP.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/tcp_plugin_scenario.sh"
prepare_tcp_plugin_test
srcmac="$(ip netns exec "$NS_TX" cat "/sys/class/net/${VETH_TX}/address")"
dstmac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
for outer in 4 6; do
    osrc="$TX_IP4"; odst="$RX_IP4"
    if [ "$outer" = 6 ]; then osrc="$TX_IP6"; odst="$RX_IP6"; fi
    for side in tx rx; do
        if [ "$side" = tx ]; then ns="$NS_TX"; dev="$VETH_TX"; local_ip="$osrc"; remote="$odst"; host=1; else ns="$NS_RX"; dev="$VETH_RX"; local_ip="$odst"; remote="$osrc"; host=2; fi
        ip -n "$ns" link add vxlan7 type vxlan id 7 local "$local_ip" remote "$remote" dev "$dev" dstport 4789
        ip -n "$ns" link set vxlan7 up
        ip -n "$ns" addr add "192.168.120.${host}/24" dev vxlan7
        ip -n "$ns" -6 addr add "fd00:120::${host}/64" dev vxlan7 nodad
    done
    ism="$(ip netns exec "$NS_TX" cat /sys/class/net/vxlan7/address)"
    idm="$(ip netns exec "$NS_RX" cat /sys/class/net/vxlan7/address)"
    for inner in 4 6; do
        isrc=192.168.120.1; idst=192.168.120.2
        if [ "$inner" = 6 ]; then isrc=fd00:120::1; idst=fd00:120::2; fi
        modes=lco
        if [ "$outer" = 4 ]; then modes='zero lco'; fi
        for mode in $modes; do
            endpoint="${idst}:${DST_PORT}"
            if [ "$inner" = 6 ]; then endpoint="[${idst}]:${DST_PORT}"; fi
            # Force the return SYN-ACK to resolve the peer through ARP/ND.
            ip -n "$NS_TX" neigh flush dev vxlan7
            ip -n "$NS_RX" neigh flush dev vxlan7
            start_sink "$endpoint"
            config="$(python3 "${TCP_PY_DIR}/config.py" vxlan "$srcmac" "$dstmac" "$osrc" "$odst" "$ism" "$idm" "$isrc" "$idst" "$mode" "$DST_PORT" "$TX_IP4" "$RX_IP4")"
            report="${XDPERF_EXAMPLE_RUNDIR}/vxlan-${outer}-${inner}-${mode}.csv"
            TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/vxlan-${outer}-${inner}-${mode}.log"
            run_tcp_plugin "$config" "$report" --recv --count 100000 --pps 4000 --parallelism 1
            stop_sink
            python3 "${TCP_PY_DIR}/verify.py" template "$report" "$SINK_LOG"
            print_success "TCP VXLAN outer IPv${outer}, inner IPv${inner}, checksum=${mode}: flows/bytes verified"
        done
    done
    ip -n "$NS_TX" link del vxlan7
    ip -n "$NS_RX" link del vxlan7
done
