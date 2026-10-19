# VXLAN 内の TCP フロー

```bash
make build
sudo examples/tcp-vxlan/test.sh
```

veth 両端の netns に Linux vxlan デバイスを置く。
xdperf はプラグインの外側 Ethernet/IP/UDP/VXLAN と内側 Ethernet/IP/TCP のひな型を使い、受信側は vxlan デバイスの内側で xdperf-sink を動かす。
戻りの VXLAN フレームは xdperf が XDP で解析し、内側タプルで照合する。

外側 IPv4 では UDP checksum の zero/lco、外側 IPv6 では lco を使い、内側 IPv4/IPv6 と組み合わせた 6 ケースを検証する。
各ケースの前に内側の近隣キャッシュを空にし、`--recv` 有効時も ARP/ND をホストへ渡して接続できることを確認する。
各ケースで 4 フロー、77,830 バイトの完了とシンクの受信を照合する。
UDP 送信元ポートはフロー番号により 49152 から変化する。
`tcp_encapsulation` は mixed.go サンプルへの設定名であり、SDK 上では `tcp_flow.encapsulation` に対応する。

GENEVE、二重 VXLAN、256 バイト上限、IPIP/GRE/SRv6/GTP-U/MPLS の送信更新は `TestTCPEncapBPF` で検証する。
これらのうち VXLAN/GENEVE 以外のカプセル化を持つ応答の解析は後続段階である。
