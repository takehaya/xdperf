# パケットと TCP フローの混合バリアント

この文書は混合配分の設計を示す。
現在の SDK の使い方は [混合送信ガイド](mixed_variants.md)、ひな型とトンネルの詳細は [TCP フローひな型](design_tcp_flow_template.md) を参照する。
ひな型、複数宛先、Timestamps、ペイロードパターン、フロー別 variable_params は実装済みである。

## JSON と互換性

`template_type: "variable"` の `PacketVariantSet` に種類を追加する。
`kind` の省略または `packet` は既存の base_packet / variable_params / checksums を使う。
`kind: "tcp_flow"` は `tcp_flow: {"destination":"192.0.2.2:5201","flows":[{"bytes":"65536"},{"bytes":"67108864"}]}` を持つ。
bytes は uint64 の十進文字列で、0 は count または duration を指定した無制限フローである。
フローの配列順が送信記録の flow 番号に対応する。
TCP バリアントを複数指定した場合はバリアント順に連結する。

weight は送信 worker の TX イテレーションを配分する正の整数である。
TCP の待機中も機会を消費し、パケット側に振り替えない。
TCP を含む混合集合は pattern=mixed を要求し、TCP バリアント間とパケット全体の選択には整数の重み付き乱数を使う。
パケット側の内部選択は既存の重み付き diff プールを使うため、有限プールによる丸めがある。
既存のパケット専用 JSON と raw テンプレートは引き続き使用でき、従来の未知フィールドも許容する。
TCP フローを含む応答では未知フィールドと重複キーを拒否し、32 MiB の応答上限とフロー配列の要素数を SDK 型へのデコード前に検査する。
旧ホストでの新 TCP バリアントの実行はサポートしない。
独立した TCP シナリオのテンプレートと専用リクエストは使用できない。
--tcp とプラグインの併用も受け付けない。

## 現在の対応範囲

混合送信は --plugin だけで選択し、--tcp は従来の CLI 指定による TCP 専用送信として残す。
TCP 宛先はグループごとに IP リテラルとポートを指定できる。
base_packet を省略したグループは Go が経路と近隣情報を解決してヘッダを作る。
指定したグループはプラグインの Ethernet から TCP 固定ヘッダまでを使い、destination は省略できる。
ひな型の構造、送信デバイスの MTU、MSS、固定オプション、カプセル化の修正表を検証する。
variable_params は内側送信元 IP のフロー別変更だけを許し、checksums は受け付けない。
seq、ack、flags、window、送信元ポート、長さ、チェックサムはエンジンが所有し、IPv4 ID は --tcp-ip-id に従う。

TCP バリアントは 1 種類以上とし、パケットバリアントは省略できる。
バリアント数は最大 16、フロー総数は送信元ポート範囲内、重み合計は uint32 の範囲内とする。
--count は packet と TCP の TX worker 送信フレーム総数の上限とする。
全 TCP フローが先に完了すれば count 未満で終了する。

共有の送信予算は CPU ごとに小分けで借用し、TCP だけの集合では担当フローがすべて閉じた worker の残りを返却する。
フロー数が worker 数より少ない場合は Warn を出し、担当のない worker は予算を借りない。
混合の `--count` の上限は 9223372036854775807 とする。
時間切れやシグナルで drain / abort する際の閉鎖用フレームは、`--count` の制限に含めない。

count 到達時は drain をせず 2×RTO の linger 後に終了し、未完了フローは Warn、既存の失敗フローがなければ exit 0 とする。
RX 側の ACK/RST、idle、build 失敗は予算に含めない。
--infinite、--rx-device、--swap-resp は拒否する。
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
PPS 制限時の drain 期限には、worker ごとの全フロー走査時間を FIN と ACK probe の再試行回数分加算する。
完了済みフローが多い場合でも、残ったフローを再訪する前に期限切れになることを防ぐ。
この機会は drain_opportunities に別計上し、通常の重み配分の分母に含めない。

live frame はパケットと TCP 双方の最大サイズより大きく確保する。
TCP が書き換えたフレームをパケット側が再利用するので、混合送信ではパケット側のベースコピー省略を無効にする。
TCP 側では固定ヘッダまで縮小してから拡張し、パケット側の内容が TCP ペイロードに残らないようゼロ化する。

## 受信構成

混合 RX の入口は TCP と既知のトンネル候補を混合 TCP RX に tail call し、内側 TCP を解析して照合する。
VXLAN、GENEVE、SRv6、GTP-U、GRE、IPIP、MPLS とカプセル化なしの応答を扱う。
ACK/RST は送信テンプレートから再構築し、外側経路やカプセル化の対称性は要求しない。
TCP のフロー照合と ACK 処理を優先し、対象外の TCP は既存どおりカーネルへ渡す。
ARP と ND の既存処理を妨げない。
パケット応答の計測は --recv 時だけ有効にする。
TCP に照合しなかった外側 UDP は --recv 時のパケット RX に渡す。
トンネル内の ARP/ND はホストへ PASS し、UDP 計測から除く。
RX の未照合理由と不正 TCP は [診断カウンター](tcp_stream.md#混合モードの-rx-診断) に分類する。
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

上記は初期実装の手順である。
base_packet、複数宛先、固定オプション、トンネル RX、Timestamps、ペイロードパターン、フロー別 variable_params は実装済みである。
バリアント別の詳細統計は未実装であり、現在の送信統計は packet/TCP の集計と TCP フロー記録を使う。

## 実行例

```bash
(cd plugins/mixed.go && GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o ../../out/bin/mixed.go.wasm .)
sudo out/bin/xdperf run --send --recv --device eth0 --plugin mixed.go --plugin-path out/bin \
  --plugin-config '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02"}' \
  --count 100000 --pps 2000 --parallelism 1 --tcp-flow-report flows.csv
sudo examples/mixed/setup.sh
sudo examples/mixed/test.sh
sudo examples/mixed/teardown.sh
```

サンプルは DNS 形式の UDP 問い合わせと 4 本の TCP フローを返す。
既定の TCP 送信量は 3 本が 65,536 バイト、1 本が 67,108,864 バイトである。
E2E は実行時間を抑えるため最後の 1 本を 262,144 バイトにし、対向 TCP シンクと UDP エコーサーバーで受信を照合する。
送信機会をパケット 3、TCP 1 に配分しても、TCP の ACK 待ちや完了済みフローの選択により実際の TCP フレーム比率は 25% 未満になる場合がある。
--count は送信上限であり、packet の diff プール長も従来どおりこの値から決める。
有限の TCP だけの集合では count と duration を省略でき、TCP だけなら duration に pps は不要である。
packet を含む集合で --duration を使う場合は --count を省略して --pps を指定する。
