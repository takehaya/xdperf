#!/bin/bash
# examples/common/veth.sh
# veth pair ユーティリティ (source して使う)

# veth pair を作成して両端を namespace に移動し up する
# Usage: create_veth_pair <veth1_name> <ns1> <veth2_name> <ns2>
create_veth_pair() {
    local veth1="$1" ns1="$2" veth2="$3" ns2="$4"

    # 冪等化: 残骸があれば消す
    ip link del "$veth1" 2>/dev/null || true
    ip link del "$veth2" 2>/dev/null || true

    ip link add "$veth1" type veth peer name "$veth2"
    ip link set "$veth1" netns "$ns1"
    ip link set "$veth2" netns "$ns2"
    ip netns exec "$ns1" ip link set "$veth1" up
    ip netns exec "$ns2" ip link set "$veth2" up

    echo "Created veth pair: $veth1 ($ns1) <-> $veth2 ($ns2)"
}

# veth に IPv4 アドレスを付与し、IPv6 を無効化する。
# IPv6 を切るのは、DAD/RS 等のカーネル発 IPv6 フレームが受信側 XDP カウンタ
# (xdp_rx は MAC を問わず IPv4/IPv6 を数える) に混入して「受信数 == 送信数」の
# 厳密比較を壊すため。
# Usage: configure_veth_v4only <namespace> <veth_name> <addr/prefix>
configure_veth_v4only() {
    local ns="$1" veth="$2" addr="$3"

    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.${veth}.disable_ipv6=1"
    ip netns exec "$ns" ip addr add "$addr" dev "$veth"

    echo "Configured $veth in $ns with $addr (IPv4 only)"
}
