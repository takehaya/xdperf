# パケットと TCP フローの混合バリアント

## JSON と互換性

`template_type: "variable"` の `PacketVariantSet` に種類を追加する。
`kind` の省略または `packet` は既存の base_packet / variable_params / checksums を使う。
`kind: "tcp_flow"` は `tcp_flow: {"destination":"192.0.2.2:5201","flows":[{"bytes":"65536"},{"bytes":"67108864"}]}` を持つ。
bytes は uint64 の十進文字列で、0 は duration を指定した無制限フローである。
フローの配列順が送信記録の flow 番号に対応する。
TCP バリアントを複数指定した場合はバリアント順に連結する。

weight は送信 worker の TX イテレーションを配分する正の整数である。
TCP の待機中も機会を消費し、パケット側に振り替えない。
第 1 段階の混合集合は pattern=mixed を要求し、TCP バリアント間とパケット全体の選択には整数の重み付き乱数を使う。
パケット側の内部選択は既存の重み付き diff プールを使うため、有限プールによる丸めがある。
既存のパケット専用 JSON と raw テンプレートは引き続き使用でき、従来の未知フィールドも許容する。
TCP フローを含む応答では未知フィールドと重複キーを拒否し、32 MiB の応答上限とフロー配列の要素数を SDK 型へのデコード前に検査する。
旧ホストでの新 TCP バリアントの実行はサポートしない。
独立した tcp_scenario テンプレート、専用リクエスト、--tcp とプラグインの併用は削除する。

## 第 1 段階の範囲

混合送信は --plugin だけで選択し、--tcp は従来の CLI 指定による TCP 専用送信として残す。
TCP 宛先は全 TCP バリアント共通の IP リテラルとポートに限定する。
TCP ヘッダは既存の Go の生成処理を使い、経路、送信インターフェース、MAC、MSS、VLAN を検証する。
TCP バリアントの base_packet、variable_params、checksums は受け付けない。
将来 base_packet の L2〜L4 を解析する際にも、seq、ack、flags、window、長さ、IP ID、チェックサムはエンジンが所有する。

混合集合にはパケットと TCP をそれぞれ 1 種類以上含める。
バリアント数は最大 16、フロー総数は送信元ポート範囲内、重み合計は uint32 の範囲内とする。
--count はパケットの diff プールサイズとして扱い、終了は全 TCP フローの完了、--duration、シグナルで決める。
--infinite と --rx-device は第 1 段階では拒否する。
--recv を指定するとパケット側の応答も統計に含める。

## BPF の送信構成

送信 worker は xdp_tx_mixed を毎回実行する。
小さな配分テーブルからパケットまたは TCP バリアントを選び、既存の xdp_tx または TCP 共通処理を使う xdp_tx_tcp_mixed に tail call する。
TCP 専用と混合の入口を別々にコンパイルし、TCP 専用の走査ループに混合モードの分岐を増やさない。
混合の入口は常に選択済みの 1 フローだけを駆動し、drain 時の全フローの走査も振り分けプログラムが行う。
パケットのチェックサム用 tail call は維持する。
分岐を独立プログラムに置くことで既存の checksum と TCP の verifier 状態空間を結合しない。

TCP バリアントごとに CPU が担当するフローをラウンドロビンで選ぶ。
同じフローを複数の TX worker が駆動しないよう、フロー番号を worker 数で分割する。
担当フローがない CPU の TCP 機会は idle になる。
再送と FIN も同じ配分を使う。
終了処理中はパケット送信を止め、TCP の drain / abort を優先する。
全 TCP フローが閉じた場合もパケット送信を止め、相手の FIN 再送に応答するための受信待機だけを続ける。
この機会は drain_opportunities に別計上し、通常の重み配分の分母に含めない。

live frame はパケットと TCP 双方の最大サイズより大きく確保する。
TCP が書き換えたフレームをパケット側が再利用するので、混合送信ではパケット側のベースコピー省略を無効にする。
TCP 側では固定ヘッダまで縮小してから拡張し、パケット側の内容が TCP ペイロードに残らないようゼロ化する。

## 受信構成

混合 RX の入口で外側 IP のプロトコルを識別し、TCP と UDP をそれぞれ既存の TCP RX とパケット RX に tail call する。
TCP のフロー照合と ACK 処理を優先し、対象外の TCP は既存どおりカーネルへ渡す。
ARP と ND の既存処理を妨げない。
パケット応答の計測は --recv 時だけ有効にする。
第 1 段階の混合 RX 計測は外側 IPv4/IPv6 の直下にある UDP に限定し、ICMP や IPv6 拡張ヘッダ配下の UDP はカーネルへ渡す。
パケット専用モードの既存 RX は変更しない。

## 統計と送信記録

パケット側の送信数とバイト数は既存の tx_stats_map に置く。
TCP は既存の tcp_stats_map とフローの ledger を使う。
混合統計にはそれぞれの送信機会、実際のパケット送信数、TCP TX フレーム数、TCP RX が返した ACK 数、実際の TCP TX フレーム比率を表示する。
比率の分母はパケット TX と TCP worker TX の合計であり、RX が即座に返す ACK は別表示する。
これらは XDP_TX を返した回数であり、NIC や対向の受信数は E2E で別に照合する。
--tcp-flow-report は TCP のみの CSV として維持し、UDP を擬似フローに変換しない。

## 実装順序と検証

1. 独立シナリオ API を削除し、バリアント JSON と入力検証へ置き換える。
2. BPF の配分、RX の振り分け、既存 TCP ライフサイクルへの接続を実装する。
3. DNS 風 UDP と大小の TCP フローを混ぜるサンプルを追加する。
4. JSON 境界値、配分比率、マップ初期化、veth での TCP 完了と UDP 受信数を検証する。
5. 既存の全テスト、OCR、Copilot レビュー、CI を通す。

後続段階では TCP の base_packet 入力、複数宛先、バリアント別の詳細統計を追加する。

## 実行例

```bash
(cd plugins/mixed.go && GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o ../../out/bin/mixed.go.wasm .)
sudo out/bin/xdperf run --send --recv --device eth0 --plugin mixed.go --plugin-path out/bin \
  --plugin-config '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02"}' \
  --count 128 --pps 2000 --parallelism 1 --tcp-flow-report flows.csv
sudo examples/mixed/test.sh
```

サンプルは DNS 形式の UDP 問い合わせと 4 本の TCP フローを返す。
既定の TCP 送信量は 3 本が 65,536 バイト、1 本が 67,108,864 バイトである。
E2E は実行時間を抑えるため最後の 1 本を 262,144 バイトにし、対向 TCP シンクと UDP エコーサーバーで受信を照合する。
送信機会をパケット 3、TCP 1 に配分しても、TCP の ACK 待ちや完了済みフローの選択により実際の TCP フレーム比率は 25% 未満になる場合がある。
--count はこの混合モードでは送信総数ではなく diff プールサイズである。
--duration を使う場合は既存 CLI に従い --count を省略して --pps を指定する。
