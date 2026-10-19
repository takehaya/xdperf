# TCP フローのオプションとペイロード

`make build` 後に `sudo ./examples/tcp-payload/test.sh` で実行する。
IPv4 と IPv6 のそれぞれで Timestamps の合意と非合意、3 バイトの繰り返しパターン、フロー別送信元 IP、三機能の併用、ACK 損失下の併用を確認する。
Linux TCP の受信側は `sink.py` で全バイトをストリーム位置に照らして検査し、4 フローの完了と合計 77,830 バイトを照合する。
再送の位置とチェックサムは BPF_PROG_RUN のテストでも独立に検証する。

`mixed.go` のプラグイン設定に `timestamps: true`、base64 の `payload_pattern`、`flow_variable_params` を指定する。
`flow_variable_params` の位置は Ethernet フレーム先頭からのオフセットで、現状は内側送信元 IP の範囲だけを受理する。
詳細は [設計書](../../docs/ja/design_tcp_flow_template.md) を参照する。
