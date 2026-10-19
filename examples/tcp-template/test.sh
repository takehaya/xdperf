#!/bin/bash
# Plugin-provided TCP templates against the Linux TCP stack.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NS_TX=xdperf-tmpl-tx NS_RX=xdperf-tmpl-rx VETH_TX=tmpl-tx VETH_RX=tmpl-rx
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"
check_root
check_xdperf_built
trap teardown_tcp_topology EXIT
setup_tcp_topology
# QinQ leaves the outer 802.1ad tag visible to XDP on common veth paths.
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
    config="$(python3 - "$srcmac" "$dstmac" "$src" "$dst" "$tags" "$DST_PORT" "$TX_IP4" "$RX_IP4" <<'PY'
import base64,ipaddress,json,struct,sys
sm,dm,src,dst,tags,port,udp_src,udp_dst=sys.argv[1:]
src,dst=ipaddress.ip_address(src),ipaddress.ip_address(dst)
tags=int(tags)
b=bytes.fromhex(dm.replace(':','')+sm.replace(':',''))
if tags==1: b+=struct.pack('!HH',0x8100,110)
if tags==2: b+=struct.pack('!HHHH',0x88a8,120,0x8100,121)
b+=struct.pack('!H',0x800 if src.version==4 else 0x86dd)
if src.version==4: b+=struct.pack('!BBHHHBBH4s4s',0x45,0xa8,40,0x1234,0x4000,37,6,0,src.packed,dst.packed)
else: b+=struct.pack('!IHBB16s16s',0x6ac12345,20,6,37,src.packed,dst.packed)
b+=struct.pack('!HHIIBBHHH',0,int(port),0,0,0x50,0,0,0,0)
print(json.dumps(dict(src_ip=udp_src,dst_ip=udp_dst,dst_mac=dm,small_bytes='4097',large_bytes='65539',tcp_base=dict(data=base64.b64encode(b).decode(),length=len(b)),syn_options='BAIBAQ==',data_options='AQEBAQ==')))
PY
)"
    report="${XDPERF_EXAMPLE_RUNDIR}/template-${mode}.csv"
    TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/template-${mode}.log"
    if ! ip netns exec "$NS_TX" "$XDPERF_BIN" run --send --device "$VETH_TX" \
        --plugin mixed.go --plugin-path "$PLUGIN_PATH" --plugin-config "$config" \
        --count 128 --pps 4000 --parallelism 1 --tcp-flow-report "$report" > "$TX_LOG" 2>&1; then
        tail -n 40 "$TX_LOG"; exit 1
    fi
    stop_sink
    python3 - "$report" "$SINK_LOG" <<'PY'
import csv,json,sys
rows=list(csv.DictReader(open(sys.argv[1])))
sink=json.loads(open(sys.argv[2]).readlines()[-1])
assert len(rows)==4 and all(r['state']=='done' for r in rows),rows
assert [int(r['bytes_acked']) for r in rows]==[4097]*3+[65539],rows
assert sink['accepted']==sink['closed']==4 and sink['bytes']==77830,sink
PY
    print_success "TCP template ${mode}: all flows and bytes verified"
done
