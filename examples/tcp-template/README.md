# TCP フローひな型の E2E

```bash
make build
sudo examples/tcp-template/test.sh
```

mixed.go の `tcp_base` に TCP 固定ヘッダまでの Ethernet フレームを渡す。
`syn_options` と `data_options` は base64 の固定オプション列を受け取る。
プラグインは `tcp_flow` バリアントの `base_packet` に変換し、宛先はホストがひな型から取得する。

テストは IPv4/IPv6 とタグなし、VLAN、QinQ の 6 ケースを実行する。
各ケースでカーネル TCP のシンクが受信した 4 フロー、77,830 バイトと、送信側の完了記録を照合する。
SYN に SACK-Permitted、データに NOP を付け、DSCP、TTL、IPv6 flow label を設定する。
ヘッダの保存とチェックサムの厳密な照合は `TestTCPTemplateBPF` が担当する。
