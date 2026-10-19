#!/bin/bash
# Optional flow features against Linux TCP, with independent payload checking.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NS_TX=xdperf-payload-tx NS_RX=xdperf-payload-rx VETH_TX=payload-tx VETH_RX=payload-rx
source "${SCRIPT_DIR}/../common/tcp_scenario.sh"
check_root
check_xdperf_built
verifier_pid=""
cleanup() {
    if [ -n "$verifier_pid" ]; then kill "$verifier_pid" 2>/dev/null || true; wait "$verifier_pid" 2>/dev/null || true; fi
    teardown_tcp_topology
}
trap cleanup EXIT
setup_tcp_topology
srcmac="$(ip netns exec "$NS_TX" cat "/sys/class/net/${VETH_TX}/address")"
dstmac="$(ip netns exec "$NS_RX" cat "/sys/class/net/${VETH_RX}/address")"
# Kernel replies to variable source IPs must resolve to the sender, too.
for n in 11 12 13 14; do
    ip -n "$NS_TX" addr add "192.168.110.${n}/32" dev "$VETH_TX"
    ip -n "$NS_TX" -6 addr add "fd00:110::${n}/128" dev "$VETH_TX" nodad
done
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
        ip netns exec "$NS_RX" python3 "${SCRIPT_DIR}/sink.py" "$dst" "$version" "$pattern" > "$verifylog" 2>&1 &
        verifier_pid=$!
        for _ in $(seq 1 50); do
            if grep -q ready "$verifylog"; then break; fi
            sleep 0.1
        done
        grep -q ready "$verifylog" || { cat "$verifylog"; exit 1; }
        config="$(python3 - "$srcmac" "$dstmac" "$src" "$dst" "$feature" "$pattern" "$TX_IP4" "$RX_IP4" <<'PY'
import base64,ipaddress,json,struct,sys
sm,dm,src,dst,feature,pattern,us,ud=sys.argv[1:]
src,dst=ipaddress.ip_address(src),ipaddress.ip_address(dst)
b=bytes.fromhex(dm.replace(':','')+sm.replace(':',''))+struct.pack('!H',0x800 if src.version==4 else 0x86dd)
if src.version==4:
    b+=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0,0x4000,64,6,0,src.packed,dst.packed)
else:
    b+=struct.pack('!IHBB16s16s',0x60000000,20,6,64,src.packed,dst.packed)
b+=struct.pack('!HHIIBBHHH',0,5201,0,0,0x50,0,0,0,0)
c=dict(src_ip=us,dst_ip=ud,dst_mac=dm,tcp_base=dict(data=base64.b64encode(b).decode(),length=len(b)),small_bytes='4097',large_bytes='65539',timestamps=feature in ('timestamps','declined','combined','loss'),payload_pattern=base64.b64encode(bytes.fromhex(pattern)).decode())
if feature in ('variables','combined','loss'):
    # IPv6 textual ::11 is hex 0x11; use corresponding low-byte values.
    first=11 if src.version==4 else 0x11
    c['flow_variable_params']=[dict(byte_start=29 if src.version==4 else 37,byte_size=1,byte_range=dict(start=first,end=first+3),pattern_type='sequential')]
print(json.dumps(c))
PY
)"
        if [ "$feature" = loss ]; then
            # Lose ACKs on the return path; retransmission bytes are also checked.
            ip netns exec "$NS_RX" tc qdisc add dev "$VETH_RX" root netem loss 5%
        fi
        report="${XDPERF_EXAMPLE_RUNDIR}/payload-${version}-${feature}.csv"
        TX_LOG="${XDPERF_EXAMPLE_RUNDIR}/payload-${version}-${feature}.log"
        if ! ip netns exec "$NS_TX" "$XDPERF_BIN" run --send --device "$VETH_TX" \
            --plugin mixed.go --plugin-path "$PLUGIN_PATH" --plugin-config "$config" \
            --count 128 --pps 4000 --parallelism 1 --tcp-flow-report "$report" > "$TX_LOG" 2>&1; then
            tail -n 50 "$TX_LOG"; exit 1
        fi
        if ! wait "$verifier_pid"; then cat "$verifylog"; exit 1; fi
        verifier_pid=""
        if [ "$feature" = loss ]; then ip netns exec "$NS_RX" tc qdisc del dev "$VETH_RX" root; fi
        stop_sink
        python3 - "$report" <<'PY'
import csv,sys
rows=list(csv.DictReader(open(sys.argv[1])))
assert len(rows)==4 and all(r['state']=='done' for r in rows),rows
assert sum(int(r['bytes_acked']) for r in rows)==77830,rows
PY
        print_success "TCP payload IPv${version} ${feature}: four streams and 77830 bytes verified"
    done
done
