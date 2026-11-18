#!/bin/bash
# docs/ja/scripts/bench_netkit_realnic.sh
# Two-node 100GbE physical NIC (mlx5_core) benchmark comparing veth, netkit (L2/L3),
# and netkit + BPF redirect fastpath using xdperf (TCP stream, CPS, UDP+TCP mixed,
# and 5-tuple flow counter ledger verification).
set -euo pipefail

TX_HOST="${TX_HOST:-ipa-02-400g}"
RX_HOST="${RX_HOST:-ipa-01-400g}"
TX_DEV="${TX_DEV:-enp1s0np0}"
RX_DEV="${RX_DEV:-enp1s0np0}"
TX_IP="${TX_IP:-192.168.20.2}"
RX_HOST_IP="${RX_HOST_IP:-192.168.20.1}"
TX_CPU_POOL="${TX_CPU_POOL:-16-23}"
POD_SUBNET="${POD_SUBNET:-10.200.2.0/24}"
POD_GW="${POD_GW:-10.200.2.1}"
POD_IP="${POD_IP:-10.200.2.2}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/xdperf-netkit}"
REMOTE_BIN="${REMOTE_DIR}/bin"
DURATION="${DURATION:-3s}"
MODES="${MODES:-veth netkit-l2 netkit-l3 netkit-bpf}"
SECTIONS="${SECTIONS:-E3A E3B E3C E3D}"

ssh_tx() {
    ssh -o BatchMode=yes "${TX_HOST}" "$@"
}

ssh_rx() {
    ssh -o BatchMode=yes "${RX_HOST}" "$@"
}

cleanup_remote() {
    ssh_tx "sudo bash -c '
        ip route del ${POD_SUBNET} via ${RX_HOST_IP} dev ${TX_DEV} 2>/dev/null || true
        if [[ \"${TX_HOST}\" == ipa-* ]]; then
            ip addr flush dev ${TX_DEV} 2>/dev/null || true
            ip link set ${TX_DEV} down 2>/dev/null || true
        fi
    '" || true
    ssh_rx "sudo bash -c '
        kill -INT \$(cat ${REMOTE_DIR}/sink.pid 2>/dev/null) \$(cat ${REMOTE_DIR}/fp.pid 2>/dev/null) 2>/dev/null || true
        sleep 0.2
        while iptables -D FORWARD -i ${RX_DEV} -j ACCEPT 2>/dev/null; do :; done
        while iptables -D FORWARD -o ${RX_DEV} -j ACCEPT 2>/dev/null; do :; done
        ip netns del b-rx 2>/dev/null || true
        ip link del edut 2>/dev/null || true
        rm -f ${REMOTE_DIR}/sink.pid ${REMOTE_DIR}/fp.pid
        if [[ \"${RX_HOST}\" == ipa-* ]]; then
            ip addr flush dev ${RX_DEV} 2>/dev/null || true
            ip link set ${RX_DEV} down 2>/dev/null || true
        fi
    '" || true
}
trap cleanup_remote EXIT

setup_mode() {
    local mode="$1"
    ssh_rx "sudo bash -e -c '
        kill -INT \$(cat ${REMOTE_DIR}/sink.pid 2>/dev/null) \$(cat ${REMOTE_DIR}/fp.pid 2>/dev/null) 2>/dev/null || true
        sleep 0.2
        ip link set ${RX_DEV} up
        ip addr replace ${RX_HOST_IP}/24 dev ${RX_DEV}
        sysctl -qw net.ipv4.ip_forward=1
        iptables -C FORWARD -i ${RX_DEV} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i ${RX_DEV} -j ACCEPT
        iptables -C FORWARD -o ${RX_DEV} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o ${RX_DEV} -j ACCEPT
        ip netns del b-rx 2>/dev/null || true
        ip link del edut 2>/dev/null || true
        rm -f ${REMOTE_DIR}/sink.pid ${REMOTE_DIR}/fp.pid ${REMOTE_DIR}/flow5.json ${REMOTE_DIR}/sink.log ${REMOTE_DIR}/fp.log

        ip netns add b-rx
        ip -n b-rx link set lo up
        ip netns exec b-rx sysctl -qw net.core.somaxconn=8192 net.ipv4.tcp_max_syn_backlog=8192

        add_netkit() {
            local primary=\"\$1\" peer=\"\$2\" nkmode=\"\$3\" ns=\"\$4\"
            if ip link add \"\${primary}\" type netkit mode \"\${nkmode}\" peer \"\${peer}\" netns \"\${ns}\" 2>/dev/null; then
                return 0
            fi
            python3 - \"\${primary}\" \"\${peer}\" \"\${nkmode}\" <<\"PY\"
import os, socket, struct, sys
primary, peer, mode_str = sys.argv[1], sys.argv[2], sys.argv[3]
mode = 0 if mode_str == \"l2\" else 1
def nla(t, data):
    l = 4 + len(data)
    return struct.pack(\"HH\", l, t) + data + (b\"\\x00\" * ((4 - (l % 4)) % 4))
ifinfomsg = struct.pack(\"BBHiII\", socket.AF_UNSPEC, 0, 0, 0, 0, 0)
peer_msg = ifinfomsg + nla(3, peer.encode() + b\"\\x00\")
info_data = nla(5, struct.pack(\"I\", mode)) + nla(1, peer_msg)
linkinfo = nla(1, b\"netkit\\x00\") + nla(2, info_data)
payload = ifinfomsg + nla(3, primary.encode() + b\"\\x00\") + nla(18, linkinfo)
nlmsg = struct.pack(\"IHHII\", 16 + len(payload), 16, 1 | 4 | 0x200 | 0x400, 1, 0) + payload
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
s.send(nlmsg)
resp = s.recv(4096)
err = struct.unpack(\"i\", resp[16:20])[0]
if err != 0:
    raise OSError(-err, os.strerror(-err))
PY
            ip link set \"\${peer}\" netns \"\${ns}\"
        }

        if [ \"${mode}\" = \"veth\" ]; then
            ip link add edut numtxqueues 16 numrxqueues 16 type veth peer name erx numtxqueues 16 numrxqueues 16 netns b-rx
            sysctl -qw net.ipv6.conf.edut.disable_ipv6=1
            ip netns exec b-rx sysctl -qw net.ipv6.conf.erx.disable_ipv6=1
            ip addr add ${POD_GW}/24 dev edut
            ip link set edut up
            ip -n b-rx addr add ${POD_IP}/24 dev erx
            ip -n b-rx link set erx up
            ip -n b-rx route add default via ${POD_GW}
        elif [ \"${mode}\" = \"netkit-l2\" ]; then
            add_netkit edut erx l2 b-rx
            sysctl -qw net.ipv6.conf.edut.disable_ipv6=1
            ip netns exec b-rx sysctl -qw net.ipv6.conf.erx.disable_ipv6=1
            ip addr add ${POD_GW}/24 dev edut
            ip link set edut up
            ip -n b-rx addr add ${POD_IP}/24 dev erx
            ip -n b-rx link set erx up
            ip -n b-rx route add default via ${POD_GW}
        elif [ \"${mode}\" = \"netkit-l3\" ] || [ \"${mode}\" = \"netkit-bpf\" ] || [ \"${mode}\" = \"netkit-bpf+flow5\" ]; then
            add_netkit edut erx l3 b-rx
            sysctl -qw net.ipv6.conf.edut.disable_ipv6=1
            ip netns exec b-rx sysctl -qw net.ipv6.conf.erx.disable_ipv6=1
            ip link set edut up
            ip route replace ${POD_IP}/32 dev edut
            ip -n b-rx addr add ${POD_IP}/32 dev erx
            ip -n b-rx link set erx up
            ip -n b-rx route add default dev erx
            if [ \"${mode}\" = \"netkit-bpf\" ]; then
                nohup ${REMOTE_BIN}/xdperf-sink -proto udp -listen 127.0.0.1:19998 -interval 0 \
                    -netkit-fastpath ${RX_DEV}:edut:${POD_IP} >${REMOTE_DIR}/fp.log 2>&1 &
                echo \$! > ${REMOTE_DIR}/fp.pid
            elif [ \"${mode}\" = \"netkit-bpf+flow5\" ]; then
                nohup ${REMOTE_BIN}/xdperf-sink -proto udp -listen 127.0.0.1:19998 -interval 0 \
                    -netkit-fastpath ${RX_DEV}:edut:${POD_IP} \
                    -netkit-flow-dump ${REMOTE_DIR}/flow5.json >${REMOTE_DIR}/fp.log 2>&1 &
                echo \$! > ${REMOTE_DIR}/fp.pid
            fi
        fi

        nohup ip netns exec b-rx ${REMOTE_BIN}/xdperf-sink -proto both -listen ${POD_IP}:5201 -interval 0 >${REMOTE_DIR}/sink.log 2>&1 &
        echo \$! > ${REMOTE_DIR}/sink.pid
        for _ in \$(seq 1 50); do
            if grep -q listening ${REMOTE_DIR}/sink.log 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        if [ -f ${REMOTE_DIR}/fp.pid ]; then
            for _ in \$(seq 1 50); do
                if grep -q listening ${REMOTE_DIR}/fp.log 2>/dev/null; then
                    break
                fi
                sleep 0.1
            done
        fi
    '"
    ssh_tx "sudo bash -e -c '
        rm -f ${REMOTE_DIR}/tx.log ${REMOTE_DIR}/flows.csv
        ip link set ${TX_DEV} up
        ip addr replace ${TX_IP}/24 dev ${TX_DEV}
        ok=0
        for _ in \$(seq 1 20); do
            if ip route replace ${POD_SUBNET} via ${RX_HOST_IP} dev ${TX_DEV} 2>/dev/null &&
               ping -c 1 -W 1 ${POD_IP} >/dev/null 2>&1; then
                ok=1
                break
            fi
            sleep 0.3
        done
        [ \"\$ok\" -eq 1 ]
    '"
}

rx_softnet_processed() {
    ssh_rx 'python3 -c "
with open(\"/proc/net/softnet_stat\") as f:
    print(sum(int(line.split()[0], 16) for line in f if line.strip()))
"'
}

if [[ " ${SECTIONS} " == *" E3A "* ]]; then
echo "=== E3-A: 100GbE Sustained TCP Stream (${TX_HOST} -> ${RX_HOST}, ${DURATION}) ==="
printf "%-12s | %-6s | %-5s | %-4s | %-6s | %-10s | %-12s | %-6s | %-12s\n" \
    "Mode" "Worker" "Flows" "Win" "IP_ID" "Goodput" "Data Segs/s" "RTX" "RX Softnet/seg"
for mode in $MODES; do
    for cfg_item in "1:16:32:flow" "1:16:32:shared" "4:64:32:flow" "4:64:32:shared" "8:256:8:flow" "8:256:8:shared"; do
        IFS=":" read -r workers flows win ip_id <<< "$cfg_item"
        setup_mode "$mode"
        s_before="$(rx_softnet_processed)"
        ssh_tx "sudo ${REMOTE_BIN}/xdperf run --device ${TX_DEV} \
            --plugin tcpflow.go --plugin-path ${REMOTE_BIN} \
            --parallelism ${workers} --cpu-mode ${TX_CPU_POOL} --duration ${DURATION} \
            --cfg '{\"dst_ip\":\"${POD_IP}\",\"tcp_port\":5201,\"flows\":${flows},\"bytes\":\"0\",\"window_segs\":${win},\"ip_id\":\"${ip_id}\"}' \
            >${REMOTE_DIR}/tx.log 2>&1"
        s_after="$(rx_softnet_processed)"
        s_delta=$(( s_after - s_before ))
        ssh_tx "python3 - '$mode' '$workers' '$flows' '$win' '$ip_id' '$s_delta' ${REMOTE_DIR}/tx.log <<'PY'
import json, sys
mode, workers, flows, win, ip_id, s_delta, tx_log = sys.argv[1:]
s_delta = int(s_delta)
with open(tx_log) as f:
    lines = f.readlines()
stats = json.loads(next(l[l.index('{'):] for l in lines if 'tcp final statistics' in l))
rates = json.loads(next(l[l.index('{'):] for l in lines if 'tcp connection rates' in l))
sec = rates['load_seconds']
gbps = stats['bytes_acked'] * 8 / sec / 1e9
segs_s = stats['data_segments'] / sec
rtx = stats['retransmits']
per_seg = s_delta / max(1, stats['data_segments'])
print(f'{mode:12s} | {workers:6s} | {flows:5s} | {win:4s} | {ip_id:6s} | {gbps:6.3f} Gbps | {segs_s:10.0f}/s | {rtx:6d} | {per_seg:10.2f}')
PY"
    done
done
fi

if [[ " ${SECTIONS} " == *" E3B "* ]]; then
echo ""
echo "=== E3-B: 100GbE Short-lived TCP Connection Rate / CPS (${DURATION}, 1 KiB/conn) ==="
printf "%-12s | %-6s | %-5s | %-12s | %-12s | %-6s | %-12s\n" \
    "Mode" "Worker" "Slots" "Done CPS" "Completed" "RTX" "RX Softnet/conn"
for cfg_item in "1:64" "4:256"; do
    IFS=":" read -r workers slots <<< "$cfg_item"
    for mode in $MODES; do
        setup_mode "$mode"
        s_before="$(rx_softnet_processed)"
        ssh_tx "sudo ${REMOTE_BIN}/xdperf run --device ${TX_DEV} \
            --plugin tcpflow.go --plugin-path ${REMOTE_BIN} \
            --parallelism ${workers} --cpu-mode ${TX_CPU_POOL} --duration ${DURATION} \
            --cfg '{\"dst_ip\":\"${POD_IP}\",\"tcp_port\":5201,\"flows\":${slots},\"bytes\":\"1024\",\"connections\":0,\"window_segs\":4,\"port_reuse_delay_ms\":1000}' \
            >${REMOTE_DIR}/tx.log 2>&1"
        s_after="$(rx_softnet_processed)"
        s_delta=$(( s_after - s_before ))
        ssh_tx "python3 - '$mode' '$workers' '$slots' '$s_delta' ${REMOTE_DIR}/tx.log <<'PY'
import json, sys
mode, workers, slots, s_delta, tx_log = sys.argv[1:]
s_delta = int(s_delta)
with open(tx_log) as f:
    lines = f.readlines()
stats = json.loads(next(l[l.index('{'):] for l in lines if 'tcp final statistics' in l))
rates = json.loads(next(l[l.index('{'):] for l in lines if 'tcp connection rates' in l))
cps = rates['done_cps']
done = stats['done']
rtx = stats['retransmits']
per_conn = s_delta / max(1, done)
print(f'{mode:12s} | {workers:6s} | {slots:5s} | {cps:10.1f}/s | {done:12d} | {rtx:6d} | {per_conn:10.2f}')
PY"
    done
done
fi

if [[ " ${SECTIONS} " == *" E3C "* ]]; then
echo ""
echo "=== E3-C: 100GbE Mixed High-PPS UDP Flood (75%) + 4 TCP Streams (25%, 3x256KiB + 1x2MiB = 2.75MiB, 250k PPS) ==="
printf "%-12s | %-6s | %-9s | %-11s | %-6s | %-10s | %-18s | %-12s\n" \
    "Mode" "Done" "TCP Time" "TCP Goodput" "RTX" "UDP TX" "UDP RX (Delivery)" "RX Softnet/pkt"
rx_mac="$(ssh_rx "cat /sys/class/net/${RX_DEV}/address")"
for mode in $MODES; do
    setup_mode "$mode"
    s_before="$(rx_softnet_processed)"
    ssh_tx "sudo ${REMOTE_BIN}/xdperf run --send --device ${TX_DEV} \
        --plugin mixed.go --plugin-path ${REMOTE_BIN} \
        --plugin-config '{\"src_ip\":\"${TX_IP}\",\"dst_ip\":\"${POD_IP}\",\"dst_mac\":\"${rx_mac}\",\"tcp_port\":5201,\"udp_port\":5201,\"small_bytes\":\"262144\",\"large_bytes\":\"2097152\",\"packet_weight\":3,\"tcp_weight\":1,\"window_segs\":8,\"mss\":1448}' \
        --tcp-flow-report ${REMOTE_DIR}/flows.csv --count 2000000 --pps 250000 --parallelism 1 --cpu-mode ${TX_CPU_POOL} \
        >${REMOTE_DIR}/tx.log 2>&1"
    s_after="$(rx_softnet_processed)"
    s_delta=$(( s_after - s_before ))
    ssh_rx "sudo bash -c 'kill -INT \$(cat ${REMOTE_DIR}/sink.pid) 2>/dev/null || true; sleep 0.3'"
    sink_last="$(ssh_rx "tail -n 1 ${REMOTE_DIR}/sink.log")"
    ssh_tx "python3 - '$mode' '$s_delta' ${REMOTE_DIR}/tx.log '$sink_last' <<'PY'
import json, sys
mode, s_delta, tx_log, sink_last = sys.argv[1:]
s_delta = int(s_delta)
with open(tx_log) as f:
    lines = f.readlines()
tstats = json.loads(next(l[l.index('{'):] for l in lines if 'tcp final statistics' in l))
mstats = json.loads(next(l[l.index('{'):] for l in lines if 'mixed final statistics' in l))
rates = json.loads(next(l[l.index('{'):] for l in lines if 'tcp connection rates' in l))
sink = json.loads(sink_last)
sec = rates['load_seconds']
gbps = tstats['bytes_acked'] * 8 / sec / 1e9
rtx = tstats['retransmits']
done = tstats['done']
udp_tx = mstats['packet_tx']
udp_rx = sink.get('udp_packets', 0)
pct = 100.0 * udp_rx / max(1, udp_tx)
total_pkts = udp_tx + mstats['tcp_tx']
per_pkt = s_delta / max(1, total_pkts)
print(f'{mode:12s} | {done:3d}/4  | {sec:8.3f}s | {gbps:6.3f} Gbps | {rtx:6d} | {udp_tx:10d} | {udp_rx:9d} ({pct:5.1f}%) | {per_pkt:10.2f}')
PY"
done
fi

if [[ " ${SECTIONS} " == *" E3D "* ]]; then
echo ""
echo "=== E3-D1: 100GbE netkit BPF 5-Tuple Flow Counter (LRU_HASH) Overhead (${DURATION}) ==="
printf "%-16s | %-6s | %-5s | %-6s | %-10s | %-12s | %-6s\n" \
    "Mode" "Worker" "Flows" "IP_ID" "Goodput" "Data Segs/s" "RTX"
for cfg_item in "1:16:32:flow" "1:16:32:shared" "4:64:32:flow" "4:64:32:shared"; do
    IFS=":" read -r workers flows win ip_id <<< "$cfg_item"
    for mode in netkit-bpf netkit-bpf+flow5; do
        setup_mode "$mode"
        ssh_tx "sudo ${REMOTE_BIN}/xdperf run --device ${TX_DEV} \
            --plugin tcpflow.go --plugin-path ${REMOTE_BIN} \
            --parallelism ${workers} --cpu-mode ${TX_CPU_POOL} --duration ${DURATION} \
            --cfg '{\"dst_ip\":\"${POD_IP}\",\"tcp_port\":5201,\"flows\":${flows},\"bytes\":\"0\",\"window_segs\":${win},\"ip_id\":\"${ip_id}\"}' \
            >${REMOTE_DIR}/tx.log 2>&1"
        ssh_tx "python3 - '$mode' '$workers' '$flows' '$ip_id' ${REMOTE_DIR}/tx.log <<'PY'
import json, sys
mode, workers, flows, ip_id, tx_log = sys.argv[1:]
with open(tx_log) as f:
    lines = f.readlines()
stats = json.loads(next(l[l.index('{'):] for l in lines if 'tcp final statistics' in l))
rates = json.loads(next(l[l.index('{'):] for l in lines if 'tcp connection rates' in l))
sec = rates['load_seconds']
gbps = stats['bytes_acked'] * 8 / sec / 1e9
segs_s = stats['data_segments'] / sec
rtx = stats['retransmits']
print(f'{mode:16s} | {workers:6s} | {flows:5s} | {ip_id:6s} | {gbps:6.3f} Gbps | {segs_s:10.0f}/s | {rtx:6d}')
PY"
    done
done

echo ""
echo "=== E3-D2: 100GbE netkit BPF 5-Tuple Counter vs --tcp-flow-report Ledger Verification ==="
printf "%-28s | %-6s | %-10s | %-10s | %-8s | %-14s | %-14s\n" \
    "Workload" "Flows" "Fwd Wire" "TCX In" "GRO Rat" "Ingress Match" "Egress Match"
for item in \
    "1:16:16:flow:TCP 16x10segs (win16,flow)" \
    "1:16:16:shared:TCP 16x10segs (win16,shared)" \
    "1:128:1:flow:TCP 128x10segs (win1,1w)" \
    "4:256:1:flow:TCP 256x10segs (win1,4w)"; do
    IFS=":" read -r w fl win ip_id label <<< "$item"
    setup_mode "netkit-bpf+flow5"
    ssh_tx "sudo ${REMOTE_BIN}/xdperf run --device ${TX_DEV} \
        --plugin tcpflow.go --plugin-path ${REMOTE_BIN} \
        --parallelism ${w} --cpu-mode ${TX_CPU_POOL} --tcp-flow-report ${REMOTE_DIR}/flows.csv \
        --cfg '{\"dst_ip\":\"${POD_IP}\",\"tcp_port\":5201,\"flows\":${fl},\"bytes\":\"14480\",\"window_segs\":${win},\"ip_id\":\"${ip_id}\"}' \
        >${REMOTE_DIR}/tx.log 2>&1"
    ssh_rx "sudo bash -c 'kill -INT \$(cat ${REMOTE_DIR}/fp.pid) 2>/dev/null || true; sleep 0.3'"
    scp -q "${TX_HOST}:${REMOTE_DIR}/flows.csv" /tmp/e3d_flows.csv
    scp -q "${RX_HOST}:${REMOTE_DIR}/flow5.json" /tmp/e3d_flow5.json
    python3 - "$label" /tmp/e3d_flows.csv /tmp/e3d_flow5.json <<'PY'
import csv, json, sys
label, csv_path, json_path = sys.argv[1:]
with open(csv_path, newline='') as f:
    rows = list(csv.DictReader(f))
with open(json_path) as f:
    dump = json.load(f)
in_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['ingress']}
eg_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['egress']}
fwd_wire = sum(int(r['tx_pkts']) + int(r['rx_replies']) for r in rows)
tcx_in = sum(in_map.values())
gro_ratio = fwd_wire / max(1, tcx_in)
in_ok = sum(1 for r in rows if in_map.get(('192.168.20.2', '10.200.2.2', int(r['src_port']), 5201, 6)) == int(r['tx_pkts']) + int(r['rx_replies']))
eg_ok = sum(1 for r in rows if eg_map.get(('10.200.2.2', '192.168.20.2', 5201, int(r['src_port']), 6)) == int(r['rx_pkts']))
n = len(rows)
print(f"{label:28s} | {n:6d} | {fwd_wire:10d} | {tcx_in:10d} | {gro_ratio:7.2f}x | {in_ok:4d}/{n:<4d} ({100*in_ok//n:3d}%) | {eg_ok:4d}/{n:<4d} ({100*eg_ok//n:3d}%)")
PY
done

rx_mac="$(ssh_rx "cat /sys/class/net/${RX_DEV}/address")"
setup_mode "netkit-bpf+flow5"
ssh_tx "sudo ${REMOTE_BIN}/xdperf run --send --device ${TX_DEV} \
    --plugin mixed.go --plugin-path ${REMOTE_BIN} \
    --plugin-config '{\"src_ip\":\"${TX_IP}\",\"dst_ip\":\"${POD_IP}\",\"dst_mac\":\"${rx_mac}\",\"tcp_port\":5201,\"udp_port\":5201,\"small_bytes\":\"65536\",\"large_bytes\":\"262144\",\"packet_weight\":3,\"tcp_weight\":1,\"window_segs\":1,\"mss\":1448}' \
    --tcp-flow-report ${REMOTE_DIR}/flows.csv --count 200000 --pps 20000 --parallelism 1 --cpu-mode ${TX_CPU_POOL} \
    >${REMOTE_DIR}/tx.log 2>&1"
ssh_rx "sudo bash -c 'kill -INT \$(cat ${REMOTE_DIR}/fp.pid) 2>/dev/null || true; sleep 0.3'"
scp -q "${TX_HOST}:${REMOTE_DIR}/flows.csv" /tmp/e3d_flows.csv
scp -q "${TX_HOST}:${REMOTE_DIR}/tx.log" /tmp/e3d_tx.log
scp -q "${RX_HOST}:${REMOTE_DIR}/flow5.json" /tmp/e3d_flow5.json
python3 - "Mixed 1xUDP + 4xTCP (win1)" /tmp/e3d_flows.csv /tmp/e3d_flow5.json /tmp/e3d_tx.log <<'PY'
import csv, json, sys
label, csv_path, json_path, tx_log = sys.argv[1:]
with open(csv_path, newline='') as f:
    rows = list(csv.DictReader(f))
with open(json_path) as f:
    dump = json.load(f)
with open(tx_log) as f:
    mstats = json.loads(next(l[l.index('{'):] for l in f if 'mixed final statistics' in l))
in_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['ingress']}
eg_map = {(e['src_ip'], e['dst_ip'], e['src_port'], e['dst_port'], e['proto']): e['packets'] for e in dump['egress']}
udp_tx = int(mstats['packet_tx'])
fwd_wire = sum(int(r['tx_pkts']) + int(r['rx_replies']) for r in rows) + udp_tx
tcx_in = sum(in_map.values())
gro_ratio = fwd_wire / max(1, tcx_in)
in_ok = sum(1 for r in rows if in_map.get(('192.168.20.2', '10.200.2.2', int(r['src_port']), 5201, 6)) == int(r['tx_pkts']) + int(r['rx_replies']))
if in_map.get(('192.168.20.2', '10.200.2.2', 53000, 5201, 17)) == udp_tx:
    in_ok += 1
eg_ok = sum(1 for r in rows if eg_map.get(('10.200.2.2', '192.168.20.2', 5201, int(r['src_port']), 6)) == int(r['rx_pkts']))
n_in = len(rows) + 1
n_eg = len(rows)
print(f"{label:28s} | {n_in:6d} | {fwd_wire:10d} | {tcx_in:10d} | {gro_ratio:7.2f}x | {in_ok:4d}/{n_in:<4d} ({100*in_ok//n_in:3d}%) | {eg_ok:4d}/{n_eg:<4d} ({100*eg_ok//n_eg:3d}%)")
PY
fi
