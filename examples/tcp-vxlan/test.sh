#!/bin/bash
# XDP TCP inside VXLAN, terminated by a Linux vxlan device and kernel TCP.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NS_TX=xdperf-tvx-tx NS_RX=xdperf-tvx-rx VETH_TX=tvx-tx VETH_RX=tvx-rx
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"
check_root
check_xdperf_built
trap teardown_tcp_topology EXIT
setup_tcp_topology
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
            start_sink "$endpoint"
            config="$(python3 - "$srcmac" "$dstmac" "$osrc" "$odst" "$ism" "$idm" "$isrc" "$idst" "$mode" "$DST_PORT" "$TX_IP4" "$RX_IP4" <<'PY'
import base64,ipaddress,json,struct,sys
sm,dm,osrc,odst,ism,idm,isrc,idst,mode,port,usrc,udst=sys.argv[1:]
def ip(s,d,next):
    s,d=ipaddress.ip_address(s),ipaddress.ip_address(d)
    if s.version==4: return struct.pack('!BBHHHBBH4s4s',0x45,0xa8,0,0x1234,0x4000,37,next,0,s.packed,d.packed)
    return struct.pack('!IHBB16s16s',0x6ac12345,0,next,37,s.packed,d.packed)
def eth(s,d,v): return bytes.fromhex(d.replace(':','')+s.replace(':',''))+struct.pack('!H',0x800 if v==4 else 0x86dd)
ov=ipaddress.ip_address(osrc).version
iv=ipaddress.ip_address(isrc).version
b=eth(sm,dm,ov)+ip(osrc,odst,17)
u=len(b)
b+=struct.pack('!HHHH',49152,4789,0,0)+bytes.fromhex('0800000000000700')+eth(ism,idm,iv)
l3=len(b)
b+=ip(isrc,idst,6)
l4=len(b)
b+=struct.pack('!HHIIBBHHH',0,int(port),0,0,0x50,0,0,0,0)
e=dict(inner_l3_offset=l3,inner_l4_offset=l4,lengths=[dict(offset=16 if ov==4 else 18,kind='ipv4' if ov==4 else 'ipv6',constant=l4-(14 if ov==4 else 54)),dict(offset=u+4,kind='udp',constant=l4-u)],ipv4_checksums=[14] if ov==4 else [],udp_checksums=[dict(offset=u,ip_offset=14,mode=mode)],udp_source_port=dict(offset=u,base=49152,count=16384))
print(json.dumps(dict(src_ip=usrc,dst_ip=udst,dst_mac=dm,small_bytes='4097',large_bytes='65539',tcp_base=dict(data=base64.b64encode(b).decode(),length=len(b)),tcp_encapsulation=e,syn_options='BAIBAQ==',data_options='AQEBAQ==')))
PY
)"
            report="${XDPERF_EXAMPLE_RUNDIR}/vxlan-${outer}-${inner}-${mode}.csv"
            TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/vxlan-${outer}-${inner}-${mode}.log"
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
            print_success "TCP VXLAN outer IPv${outer}, inner IPv${inner}, checksum=${mode}: flows/bytes verified"
        done
    done
    ip -n "$NS_TX" link del vxlan7
    ip -n "$NS_RX" link del vxlan7
done
