# mixed.go で UDP と TCP フローを混合する

DNS 形式の UDP 問い合わせと、送信量の異なる 4 本の TCP フローを返す Go 製 Wasm プラグインです。
`--tcp` は付けません。

```bash
make build
sudo out/bin/xdperf run --device eth0 --plugin mixed.go --plugin-path out/bin \
  --count 128 --pps 2000 --tcp-flow-report flows.csv \
  --cfg '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02"}'
```

対向にはポート 5201 で受ける TCP シンクが必要です。
UDP の応答も数える場合は `--recv` と対向の UDP エコーサーバーを使います。
接続数やバイト数はプラグインが返すため、`--tcp-dst`、`--tcp-flows`、`--tcp-bytes` は指定しません。

| 設定 | 既定値 | 意味 |
| --- | --- | --- |
| `src_ip` / `dst_ip` | `192.168.110.1` / `192.168.110.2` | UDP 側の IPv4 アドレス。tcp_base を省略した場合は dst_ip を TCP 宛先にも使う |
| `dst_mac` | `02:00:00:00:00:02` | UDP フレームの宛先 MAC |
| `udp_port` / `tcp_port` | `5353` / `5201` | UDP と、省略時の TCP 宛先ポート |
| `small_bytes` / `large_bytes` | `"65536"` / `"67108864"` | 最初の 3 フローと最後の 1 フローの送信量。uint64 の十進文字列 |
| `packet_weight` / `tcp_weight` | `3` / `1` | パケットと TCP の TX イテレーションの重み |
| `tcp_base` | なし | SDK の base_packet。data は base64、length は TCP 固定ヘッダまでの長さ |
| `tcp_encapsulation` | なし | SDK の tcp_flow.encapsulation に渡す修正表 |
| `syn_options` / `data_options` | なし | base64 の固定 TCP オプション |
| `timestamps` | `false` | TCP Timestamps の提示と合意後の使用 |
| `payload_pattern` | なし | 最大 256 バイトの base64 繰り返しパターン |
| `flow_variable_params` | なし | SDK のバリアント直下の variable_params。明示した tcp_base の内側送信元 IP をフロー別に変える |

`tcp_base` があると TCP 宛先はその内側ヘッダから取得します。
なければ `dst_ip:tcp_port` に対してホストが経路と近隣情報を解決します。
`src_ip` と `dst_mac` は UDP パケットの設定であり、この経路解決を上書きしません。
サンプルの UDP は IPv4 固定です。
TCP に IPv6 を使う場合は IPv6 の `tcp_base` を指定し、UDP 側のアドレスは IPv4 のままにします。

`--count` は Diff プールサイズで、全 TCP フロー完了、duration、シグナルが終了条件です。
重みは実際のフレーム数やバイト数の比率を保証しません。
SDK の JSON、トンネルの制限、起動時間、RX 診断は [混合送信ガイド](../../docs/ja/mixed_variants.md) を参照してください。

動作例は [mixed](../../examples/mixed/test.sh)、[TCP ひな型](../../examples/tcp-template/README.md)、[VXLAN](../../examples/tcp-vxlan/README.md)、[トンネル](../../examples/tcp-tunnels/README.md)、[ペイロード](../../examples/tcp-payload/README.md) にあります。
