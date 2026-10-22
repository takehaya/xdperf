# TCP ストリーム送信 (`tcpflow.go`)

`tcpflow.go` プラグインは、XDP で TCP 接続を開いて一方向にデータを送ります。
SYN、データ、再送、FIN は `xdp_tx_mixed` から TCP テンプレート経路へ渡し、応答は同じデバイスの `xdp_rx_mixed` が処理します。
送信側ではカーネルの TCP ソケットを使いません。
単独 `--tcp` とクライアント用の `--tcp-*` フラグは廃止しました。
設計は [design_xdp_tcp.md](design_xdp_tcp.md)、プラグイン設定は [tcpflow.go](../../plugins/tcpflow.go/README.md) を参照してください。

## 使い方

```bash
# 受信側
xdperf-sink -listen 10.0.0.2:5201

# 64 接続 × 1 GB を 4 CPU で送信
sudo xdperf run --device eth0 --plugin tcpflow.go --plugin-path out/bin \
  --parallelism 4 --tcp-flow-report flows.csv \
  --cfg '{"dst_ip":"10.0.0.2","tcp_port":5201,"flows":64,"bytes":"1000000000"}'

# IPv6、時間指定で無制限フローを閉じる (PPS は不要)
sudo xdperf run --device eth0 --plugin tcpflow.go --plugin-path out/bin --duration 30s \
  --cfg '{"dst_ip":"fd00::2","tcp_port":5201,"flows":16,"bytes":"0"}'
```

送信元 IP と宛先 MAC は経路と近隣表から決まります。
経路が `--device` の 802.1Q VLAN 子を通る場合は VLAN ID を自動で付け、PCP は 0 にします。
802.1ad などの VLAN プロトコルでは宛先だけの自動生成を拒否するため、`base_packet` にヘッダを指定してください。
アドレス、MAC、VLAN の詳細を固定する場合は `base_packet` を返すプラグインを使います (`mixed.go` の `tcp_base` など)。
`bytes` は十進文字列で指定し、k/m/g 接尾辞は使えません。

### 設定と実行上限

| tcpflow.go の設定 | 既定 | 意味 |
|---|---|---|
| `window_segs` | 32 | フローごとの飛行中セグメント数の上限 (1..65535) |
| `mss` | 自動 | MTU とヘッダ長に収まる MSS。明示値は 64..65535 |
| `rto_ms` | 200 | 再送タイムアウト (ms) |
| `ip_id` | `flow` | IPv4 ID を接続別に増やす。`shared` は TX CPU 別 |
| `port_base` | 10000 | 集合全体の送信元ポート先頭。フロー数との和は 65536 以下 |

数値の 0 は既定値を使い、`ip_id` の空文字列は `flow` を使います。
全フローが有限なら `--count` と `--duration` は省略できます。
`bytes: "0"` を含む場合は、いずれかの上限が必要です。
`--count` は SYN、再送、FIN を含む TX worker の総フレーム数の上限です。
全 TCP フローが先に完了すれば count 未満で終了します。
count 到達時は drain をせず、短い linger 後に未完了フローを警告して終了します (失敗フローがなければ終了コード 0)。
`--duration` とシグナルでは drain で接続を閉じ、この終了処理のフレームは count の対象外です。
`--pps` は待機を含む TX イテレーション数の上限で、TCP だけの duration 実行には不要です。
`--infinite`、`--rx-device`、`--swap-resp` は TCP フローと併用できません。
`--tcp-mss`、`--tcp-rto`、`--tcp-vlan-id`、`--tcp-vlan-pcp` は responder 専用で、`--tcp-server` がなければ明示指定を拒否します (環境変数も同様)。

### 出力

1 秒ごとに次の行を出します。

```
tcp: est 64 done 0 fail 0 | 9.413 Gbps acked, 812,501 segs/s, 406,114 acks/s, rtx 0/s, stalls 0/s
```

- `est` / `done` / `fail`: 確立中 / 正常終了 (相手の FIN まで ACK した) / 失敗 (RST 受信、SYN/FIN 再送上限) のフロー数
- `Gbps acked`: 直近 1 秒に相手が ACK したバイト数から求めた goodput (TCP ペイロードのみ)
- `rtx`: 再送セグメント数、`stalls`: ウィンドウ上限で送れなかった回数

終了時に `tcp final statistics` として累積値 (syn_sent, established, done, failed, data_segments,
bytes_acked, retransmits (timeout / dupack 別), acks_rcvd, acks_sent, window_stalls など) をログに出します。

### フローごとの記録 (`--tcp-flow-report`)

`--tcp-flow-report flows.csv` を付けると、終了時に 1 フロー 1 行の CSV を書き出します。フローが失敗した実行でも書き出します。

```
flow,src_port,state,tx_pkts,tx_data,tx_rtx,rx_pkts,rx_replies,bytes_acked
0,20000,done,102,100,0,104,2,144800
```

- `tx_pkts`: 送信プログラムが送ったフレーム数。SYN、データ、FIN、再送、プローブ、RST を含みます
- `tx_data`: 新しいデータセグメント数 (初回送信)、`tx_rtx`: 再送したデータセグメント数
- `rx_pkts`: 相手から受け取ったフレーム数、`rx_replies`: 受信プログラムが返した ACK / RST の数
- `bytes_acked`: 相手が ACK したペイロードのバイト数

フローが送り出したフレームは `tx_pkts + rx_replies` です。フレームを組み立ててから数えるので、組み立てに失敗したフレームは含みません (`build_errors` に計上されます)。数えるのは XDP_TX に渡した時点なので、その後のドライバや経路での損失は含みません。

Datapath Plugin のような、経路上で観測するプログラムの計数を確かめる基準に使えます。kind 上で 16,384 フローに 0.5% の損失を入れて 8,387 回の再送が起きた実行でも、Pod の出口 (cil_from_container) のフローごとのカウンタと、この記録の `tx_pkts + rx_replies` は合計・分布とも一致しました。

## 動作の要点

- 送信は既存の live frames ループをペーサーに使い、1 イテレーションで担当グループの最大 8 フローを調べて送信可能な 1 つを選び
  SYN / データ / FIN / 再送のどれかを組み立てて XDP_TX します。送るものが無ければ XDP_DROP (フレームは出ない)。
- 受信プログラムは実験フロー (宛先 IP、送信元ポート範囲、相手のポートが一致) のパケットだけを処理し、
  必要なら ACK を XDP_TX で返します。それ以外は XDP_PASS なので同じ NIC 上の他の通信に影響しません。
  実験フローのパケットは絶対にカーネルへ PASS しません (ソケットが無いので RST を打たれるため)。
- 固定ウィンドウ、重複 ACK 3 回で先頭セグメントのみ再送、RTO で go-back-N。SACK / 輻輳制御はありません。Timestamps は対応プラグインから指定できます。
- ペイロードは全ゼロです。チェックサムは擬似ヘッダと TCP ヘッダだけで決まり、セグメントの組み立ては O(1) です。
- 最後のフローが閉じたあと `2 * rto` の間は受信プログラムを残し、相手が再送した FIN に ACK を返します。
- 相手が SYN-ACK で示した MSS が自分の MSS より小さければ、そのフローはそちらを使います (トンネル経路向け)。
- 終了処理: `--duration` か 1 回目の SIGINT で drain (新規データを止めて FIN)。drain が `127 * rto + 1s` で終わらないか、2 回目の SIGINT が来たら、開いているフローに RST を送って終了します。前回の実行が残したコネクションが相手にあっても、次の実行の SYN に返る古い ACK に RST を返して作り直します。

## XDP レスポンダ (`xdperf run --tcp-server`)

受信側もカーネル TCP を使わずに XDP だけで応答するモードです。UDP の `--recv --swap-resp` (エコー) の TCP 版で、
SYN に SYN-ACK、データに ACK (中身は捨てる)、FIN に FIN+ACK を返します。相手は `tcpflow.go` クライアントでも、
socat や nc のように「一方向に送って閉じる」普通の Linux TCP クライアントでも構いません。
レスポンダはデータを送り返さないので、応答を待つクライアント (iperf3 の制御コネクション、curl など) は使えません。

```bash
# 受信側: 10.0.0.2:5201 で待つ (10.0.0.2 は eth0 に付いていること。ARP/NDP はカーネルが答える)
sudo xdperf run --tcp-server --device eth0 --tcp-listen 10.0.0.2:5201

# IPv6 の全アドレスで待つ / VLAN タグ付き / 2 セグメントごとに ACK
sudo xdperf run --tcp-server --device eth0 --tcp-listen '[::]:5201'
sudo xdperf run --tcp-server --device eth0 --tcp-listen 10.0.100.2:5201 --tcp-vlan-id 100
sudo xdperf run --tcp-server --device eth0 --tcp-listen :5201 --tcp-ack-every 2
```

| フラグ | 既定 | 意味 |
|---|---|---|
| `--tcp-server` | | XDP レスポンダを有効にする (`--recv` を含意)。`--swap-resp`、`--rx-device` とは併用不可 |
| `--tcp-listen [ip]:port` | `:5201` | 待ち受け。IP 無しは IPv4 の全アドレス、`[::]:port` は IPv6 の全アドレス |
| `--tcp-max-conns` | 262144 | フローテーブル (LRU) の大きさ |
| `--tcp-ack-every` | 1 | N 個の順序どおりのデータセグメントごとに ACK を返す。PSH / FIN 付き、重複、順序外のセグメントには常に即 ACK |
| `--tcp-mss` | 1448 / 1428 (VLAN 時 -4)、MTU 上限 | SYN-ACK で広告する MSS |
| `--tcp-sweep-after` | `max(65 * --tcp-rto, 2s)` | 最終 ACK が来ない LAST_ACK や完了しない SYN_RCVD のエントリを、最後のパケットからこの時間で片付ける (下記)。相手の FIN / SYN 再送間隔 (最大 `rto << 6`) より長くないと、生きているフローを消して RST を返してしまう |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | 0 | 802.1Q VLAN ID と PCP |
| `--duration` | | 指定時間で終了。無指定なら SIGINT / SIGTERM まで |

1 秒ごとの表示と、終了時の `tcp server final statistics` (`accepted` / `closed` / `bytes` は `xdperf-sink` の JSON と同じ意味):

```
tcp-server: active 64 accepted 64 closed 0 | 9.401 Gbps rcvd, 811,922 segs/s, 811,922 acks/s, ooo 0/s, rst 0/s
```

動作の要点:

- 待ち受けポート宛て以外は XDP_PASS なので、同じ NIC の他の通信や ARP / NDP には影響しません。待ち受けポート宛ては絶対にカーネルへ渡しません。
- タイマーを持たないので、SYN-ACK や FIN+ACK の再送は「相手が SYN / FIN を再送してきたら応答する」形です。Linux クライアントは再送してくるので実用上の問題はありません。
- 相手の最終 ACK がロスして LAST_ACK に残ったフローは、Go 側のスイーパが `--tcp-sweep-after` 後に「閉じた」と数えて削除します (`closed_implicit`)。完了しない SYN_RCVD も同様に `syn_timeouts` として削除します。終了時には経過時間に関係なく残りを数えます。
- 状態の無いセグメント (未知の相手、掃除済み、LRU で追い出された) には RST を返します。Linux クライアントは固まらずにすぐエラーになります。
- `--tcp-ack-every N` は PSH の無いセグメントを N 個ためてから ACK します。`tcpflow.go` クライアントはフロー最後とウィンドウが埋まるセグメントに PSH を付けるので停滞しませんが、PSH を付けない送信者が N 個未満で送信を止めると、相手の RTO まで ACK が出ません。N は 2〜4 程度に留めてください。
- SYN-ACK に SACK / Timestamps は付けません。広告ウィンドウは 65535、相手が Window Scale を提示していれば WS=7 を返します (受けたデータは捨てるので実質無制限)。
- フロー状態は spin lock 無しの LRU_HASH です。1 フローのパケットは NIC の RSS で同じ CPU に届く前提です。

`xdperf-sink` (カーネル TCP) と差し替えて同じ表に並べれば、「経路 (例: Cilium の NodePort) の限界」と「バックエンドの TCP スタックの限界」を切り分けられます。

### VLAN 越しの応答 (`--tcp-vlan-id` / `--tcp-vlan-pcp`)

レスポンダの相手が VLAN の先にいる場合は、`--tcp-vlan-id 100` のように相手の VID を指定します。
XDP は `eth0` などの親デバイスに付くため、レスポンダ自身が VLAN タグを扱います。
veth では、相手が VLAN サブインターフェースから送ると、802.1Q タグはフレーム内ではなく skb のメタデータ (hwaccel) に入り、XDP からはタグなしに見えます。
実 NIC の rx-vlan-offload でも同じことが起きます。
応答は受信フレームをその場で書き換えて XDP_TX で返すため、タグを補わないとタグなしの応答が出て相手に届きません。
veth やコンテナで VLAN を使う場合、この指定は事実上必須です。

指定時は、その VID のタグ付きフレームとタグなしフレームを受け付け、タグなしで届いたフレームへの応答にはタグを押し戻します。
挿入するタグの PCP は `--tcp-vlan-pcp` (既定 0) で指定し、自動設定する広告 MSS からはタグの 4 バイトを引きます。
VID 未指定 (0) では、タグ付きフレームは XDP_PASS でカーネルへ渡します。
指定できる VID は 1 つで、QinQ / 802.1ad は扱いません。

相手の設定を変えられる場合は、送信側で `ethtool -K <dev> txvlan off` としてタグをフレーム内に入れる方法もあります (レスポンダ側の VID 指定は必要です)。
送信側 (`tcpflow.go` などのプラグイン) の VLAN は、経路が 802.1Q の子を通れば自動で付き、それ以外は `base_packet` で指定します。

## 制約と注意

- 送信元 IP は `--device` (または VLAN サブインターフェース) に付いている必要があります。ARP/NDP への応答はカーネルに任せます。
- 混合 RX は内側 TCP のアドレスとポートで照合し、外側の VLAN ID は照合条件に含めません。
- veth の対向では、live frames から作られた skb にフローハッシュが付かないため、全フローが GRO の同じバケットに入る。1 バケットに保持できるのは 8 フロー (`MAX_GRO_SKBS`) までなので、`ip_id: "flow"` でも 9 フロー以上はまとめられない (kind で 8 フローは 8 セグメント/skb、9 フローは 1)。RSS でハッシュが付く実 NIC ではこの制限は無い。
- TCP フローでは `--rx-device` の分離と双方向データには未対応です。
  QinQ と各種トンネルの対応範囲は [混合送信ガイド](mixed_variants.md) を参照してください。
  `--tcp-server` はサーバからのデータ送信 (固定レスポンス) に未対応です。
- veth 上で試す場合は [examples/tcpstream](../../examples/tcpstream/README.md) の注意 (対向側に XDP プログラムが必要、ring が小さいので再送が出る) を参照してください。

## 検証 (veth)

```bash
make build
sudo examples/tcpstream/setup.sh
sudo examples/tcpstream/test.sh      # IPv4 / IPv6 / VLAN、受信側は xdperf-sink と --tcp-server の両方、socat → --tcp-server も
sudo examples/tcpstream/teardown.sh
```

## UDP と TCP の混合送信

`--plugin mixed.go` は UDP パケットと TCP フローを同じバリアント集合として返します。
使い方と設定項目は [混合送信ガイド](mixed_variants.md)、配分の設計は [混合バリアントの設計](design_mixed_variants.md)、動作確認は [E2E サンプル](../../examples/mixed/README.md) を参照してください。
混合モードは QinQ と各種トンネル、Timestamps、繰り返しペイロード、フロー別送信元 IP に対応しています。
`tcpflow.go` は全ゼロペイロードを使います。
`mixed.go` では `payload_pattern` と `timestamps` を指定できます。
`--tcp-flow-report` は混合送信でも TCP フローのみを CSV に記録します。

### 混合モードの RX 診断

`mixed final statistics` に次の累積値を表示する。全 CPU を合算したパケット数であり、正常に照合できた応答は含めない。
各パケットは以下のいずれか一つに入る。

| フィールド | 意味 |
| --- | --- |
| `rx_parse_failed` | 内側 TCP に到達できない。未対応トンネル、解析上限、長さ不整合、IPv4 オプションや断片等を含む |
| `rx_port_outside` | 内側 TCP の宛先ポートが xdperf のフロー範囲外。SSH 等の無関係な通信もここに入る |
| `rx_tuple_mismatch` | 宛先ポートはフロー範囲内だが IP の版、アドレス、送信元ポート等がひな型と一致しない。終了時に警告する |
| `rx_neighbor` | 外側・内側の ARP または IPv6 ND (ICMPv6 type 133–137) を PASS した数 |
| `rx_other` | 通常の UDP や ICMP 等、TCP 以外の通信 |
| `rx_invalid_tcp` | フローと照合後、TCP ヘッダ長、IP 長、Timestamp オプションの形式検査で DROP した数 |

`rx_tuple_mismatch` が増えた場合は、まずフローレポートと対照し、対向の待ち受けポート、IPv4/IPv6、送受信アドレス、NAT による書き換え、同じ宛先ポートを使う別通信を確認する。
応答が不足している場合は `rx_parse_failed` と `rx_invalid_tcp` も確認し、未対応トンネルやヘッダ形式、MTU による断片化、対向のトンネル設定を調べる。
これらの値だけで応答の取りこぼしや損失とは断定できない。
特に解析失敗からは、TCP や対象フローかどうかを判断できない。
`rx_parse_failed`、`rx_port_outside`、`rx_tuple_mismatch`、`rx_other` は TCP 照合を外れた時点の分類であり、既存の外側 UDP 受信処理に渡されて DROP される場合もある。
TCP チェックサムや ARP/ND 全体の妥当性を検証するカウンタではない。
ND は直接 ICMPv6 に到達できる形式が対象で、未対応の拡張ヘッダを挟むものは解析失敗に含まれる。

`--otlp-endpoint` 指定時は混合モードで `xdperf.mixed.rx` を出力する (単位 `{packet}`、累積単調増加カウンタ)。
`reason` 属性はフィールド名から `rx_` を除いた `parse_failed`、`port_outside`、`tuple_mismatch`、`neighbor`、`other`、`invalid_tcp`。
このメトリクスはプラグインを検証して混合モードを選択した後に登録する。

## 接続の繰り返しと達成 CPS

`tcpflow.go` の `connections` は、バリアント全体で試行する接続数です。
省略すると従来どおり各フローを一度実行し、正数 M を指定すると最大 M 回を試行します。
`flows` の要素数 N が同時実行枠数になり、各枠は接続の完了または失敗後に、同じ `bytes` とテンプレートで次の接続を開始します。
失敗も1回の試行として消費します。

```bash
sudo out/bin/xdperf run --device eth0 --plugin tcpflow.go --plugin-path out/bin \
  --parallelism 1 --tcp-flow-report connections.csv \
  --cfg '{"dst_ip":"192.0.2.2","flows":4,"bytes":"1024","connections":1000}'
```

`connections: 0` は `--duration` が必須です。
時間またはシグナルで新規接続を止め、開始済みの接続を既存の drain 処理で閉じます。
この途中 close は、最終ログの `reason` (`duration elapsed` / `signal`) で、予定数の完了 (`all flows closed`) と区別できます。
初版では TCP バリアント1つだけを使用でき、packet との混合、複数 TCP バリアント、`bytes: "0"`、`--count` との併用は拒否します。

枠 i の接続番号は `j = i + k * N`、送信元ポートは `port_base + j` です。
ポートは周回せず、終了済み接続の状態も実行終了まで保持します。
容量は `65536 - port_base`、既定の10000では55,536接続です。
有限 M が容量を超える場合は開始前に拒否し、時間指定中に枯渇した場合は `port_exhausted` を記録して drain 後に失敗終了します。
実行をまたいで同じ tuple をすぐに再利用しないよう、専用 netns と未使用のポート範囲または別の送信元 IP を使用してください。
共有環境での `ip_local_reserved_ports` は自動割り当てを防ぎますが、明示 bind との競合は防ぎません。
接続枠数は対向の TIME_WAIT や LB の conntrack 残留数を制限しません。
外側 UDP entropy は既存どおり接続番号 j に基づき、フロー別テンプレートは枠 i の設定を繰り返します。

`started` は初回 SYN の構築に成功した接続数で、再送を含む `syn_sent` とは別の値です。
周期表示の CPS は、開始・確立・正常完了の各カウンタ差分を実測経過秒で割ります。
最終ログの `started_cps`、`established_cps`、`done_cps` は負荷投入期間だけの値で、`load_seconds` と `drain_linger_seconds` を分けて表示します。
`--tcp-flow-report` は開始済み接続ごとに1行を出力し、`flow` は接続番号 j です。

このモードは完了を待って接続を補充するため、遅延が増えると接続発生率も下がります。
目標 CPS を指定する機能はなく、`--pps` やバリアントの weight もその代用にはなりません。
