# TCP ストリームモード (`xdperf run --tcp`)

`--tcp` は、XDP だけで実装した TCP クライアントです。SYN、データセグメント、再送、FIN をすべて
`xdp_tx_tcp` (BPF_PROG_RUN live frames) が生成し、相手の SYN-ACK / ACK / FIN は同じデバイスに
attach した `xdp_rx_tcp` が処理します。送信側ではカーネルの TCP ソケットを一切使いません。
相手は普通の Linux TCP スタック上の任意のシンク (付属の `xdperf-sink`、`socat` など) で構いません。

iperf3 のような「N 本のコネクションで一方向にデータを流して goodput を測る」用途向けです。
設計の詳細は [design_xdp_tcp.md](design_xdp_tcp.md) を参照してください。

## 使い方

```bash
# 受信側 (任意の TCP シンク)。xdperf-sink はコネクション数とバイト数を数えて終了時に JSON を出す
xdperf-sink -listen 10.0.0.2:5201

# 送信側: 64 コネクション × 1 GB を 4 CPU で流す
sudo xdperf run --tcp --device eth0 --tcp-dst 10.0.0.2:5201 \
    --tcp-flows 64 --tcp-bytes 1g --parallelism 4

# 時間指定 (フローごとのバイト数は無制限、時間が来たら全フローを FIN で閉じる)
sudo xdperf run --tcp --device eth0 --tcp-dst '[fd00::2]:5201' --tcp-flows 16 --duration 30s

# 802.1Q タグ付き
sudo xdperf run --tcp --device eth0 --tcp-dst 10.0.100.2:5201 --tcp-vlan-id 100 --tcp-flows 8 --tcp-bytes 100m
```

上の例はプラグインを使わずに実行します。
`--plugin` によるパケットと TCP の混合送信は後述します。
`--count` と `--infinite` は併用できません。

### フラグ

| フラグ | 既定 | 意味 |
|---|---|---|
| `--tcp` | | TCP ストリームモードを有効にする (`--send` を含意) |
| `--tcp-dst host:port` | 必須 | 接続先。`[v6]:port` で IPv6。アドレスファミリはここで決まる |
| `--tcp-src-ip` | 経路の preferred source | 送信元アドレス。デバイスに付いている必要がある (ARP/NDP はカーネルが応答する) |
| `--tcp-dst-mac` | ARP/NDP で解決 | ネクストホップ MAC の上書き |
| `--tcp-flows` | 1 | 同時コネクション数 (1..65536) |
| `--tcp-port-base` | 10000 | 送信元ポートの先頭。`port-base + flows <= 65536`。カーネルのエフェメラル範囲 (`net.ipv4.ip_local_port_range`) と重なると警告する (同じ宛先へのホスト自身の TCP 応答を `xdp_rx_tcp` が奪うため) |
| `--tcp-window` | 32 | フローごとの飛行中セグメント数の上限 (固定ウィンドウ)。相手の受信ウィンドウとの小さい方が効く |
| `--tcp-mss` | 1448 (IPv4) / 1428 (IPv6)、VLAN 時は -4、MTU 上限 | セグメントのペイロード長 (64 以上)。省略時はデバイス MTU に収まるよう縮める。明示した値が MTU を超えるとエラー |
| `--tcp-bytes` | 0 | フローごとの送信バイト数 (k/m/g 接尾辞可)。0 なら `--duration` まで |
| `--tcp-rto` | 200ms | 再送タイムアウト。SYN / FIN / データの再送はいずれも指数バックオフ (`rto << n`)。SYN と FIN は 6 回、データは連続 8 回で RST を送って諦める |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | 0 / 0 | 802.1Q タグ。0 でタグ無し |
| `--tcp-ip-id` | `flow` | IPv4 の ID の振り方。`flow` はコネクションごとに 1 ずつ増やす (Linux と同じ)。受信側の GRO は同じフローの連続したセグメントを 1 つの skb にまとめられる。`shared` は送信 CPU ごとに 1 つのカウンタをその CPU の全フローで共有する。1 つの CPU が 2 フロー以上を交互に送ると各フローの ID が連続しなくなり、GRO はまとめない (CPU あたり 1 フローなら `shared` でも連続するので効果はない)。受信側の設定を変えずに、パケット単位の負荷を作りたいときに使う |
| `--tcp-flow-report` | | 終了時に、フローごとの送受信の記録を CSV に書き出すパス。下の「フローごとの記録」を参照 |
| `--parallelism` | | worker CPU 数。フローは CPU 間でインターリーブして分配される |
| `--pps` | | TX イテレーション数の上限。送信しない待機イテレーションも含む |
| `--duration` | | 終了時刻。到達すると新規データを止め、全フローを FIN で閉じる (drain) |

`--tcp-bytes` と `--duration` のどちらかは必要です。両方指定すると、先に満たした方で終わります。

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

- 送信は既存の live frames ループをペーサーに使い、1 イテレーションで担当フローを 1 つ選んで
  SYN / データ / FIN / 再送のどれかを組み立てて XDP_TX します。送るものが無ければ XDP_DROP (フレームは出ない)。
- 受信プログラムは実験フロー (宛先 IP、送信元ポート範囲、相手のポートが一致) のパケットだけを処理し、
  必要なら ACK を XDP_TX で返します。それ以外は XDP_PASS なので同じ NIC 上の他の通信に影響しません。
  実験フローのパケットは絶対にカーネルへ PASS しません (ソケットが無いので RST を打たれるため)。
- 固定ウィンドウ、重複 ACK 3 回で先頭セグメントのみ再送、RTO で go-back-N。SACK / Timestamps / 輻輳制御はありません。
- ペイロードは全ゼロです。チェックサムは擬似ヘッダと TCP ヘッダだけで決まり、セグメントの組み立ては O(1) です。
- 最後のフローが閉じたあと `2 * rto` の間は受信プログラムを残し、相手が再送した FIN に ACK を返します。
- 相手が SYN-ACK で示した MSS が自分の MSS より小さければ、そのフローはそちらを使います (トンネル経路向け)。
- 終了処理: `--duration` か 1 回目の SIGINT で drain (新規データを止めて FIN)。drain が `127 * rto + 1s` で終わらないか、2 回目の SIGINT が来たら、開いているフローに RST を送って終了します。前回の実行が残したコネクションが相手にあっても、次の実行の SYN に返る古い ACK に RST を返して作り直します。

## XDP レスポンダ (`xdperf run --tcp-server`)

受信側もカーネル TCP を使わずに XDP だけで応答するモードです。UDP の `--recv --swap-resp` (エコー) の TCP 版で、
SYN に SYN-ACK、データに ACK (中身は捨てる)、FIN に FIN+ACK を返します。相手は `--tcp` クライアントでも、
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
| `--tcp-server` | | XDP レスポンダを有効にする (`--recv` を含意)。`--tcp`、`--swap-resp`、`--rx-device` とは併用不可 |
| `--tcp-listen [ip]:port` | `:5201` | 待ち受け。IP 無しは IPv4 の全アドレス、`[::]:port` は IPv6 の全アドレス |
| `--tcp-max-conns` | 262144 | フローテーブル (LRU) の大きさ |
| `--tcp-ack-every` | 1 | N 個の順序どおりのデータセグメントごとに ACK を返す。PSH / FIN 付き、重複、順序外のセグメントには常に即 ACK |
| `--tcp-mss` | 1448 / 1428 (VLAN 時 -4)、MTU 上限 | SYN-ACK で広告する MSS |
| `--tcp-sweep-after` | `max(65 * --tcp-rto, 2s)` | 最終 ACK が来ない LAST_ACK や完了しない SYN_RCVD のエントリを、最後のパケットからこの時間で片付ける (下記)。相手の FIN / SYN 再送間隔 (最大 `rto << 6`) より長くないと、生きているフローを消して RST を返してしまう |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | 0 | クライアントと同じ |
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
- `--tcp-ack-every N` は PSH の無いセグメントを N 個ためてから ACK します。`--tcp` クライアントはフロー最後とウィンドウが埋まるセグメントに PSH を付けるので停滞しませんが、PSH を付けない送信者が N 個未満で送信を止めると、相手の RTO まで ACK が出ません。N は 2〜4 程度に留めてください。
- SYN-ACK に SACK / Timestamps は付けません。広告ウィンドウは 65535、相手が Window Scale を提示していれば WS=7 を返します (受けたデータは捨てるので実質無制限)。
- フロー状態は spin lock 無しの LRU_HASH です。1 フローのパケットは NIC の RSS で同じ CPU に届く前提です。

`xdperf-sink` (カーネル TCP) と差し替えて同じ表に並べれば、「経路 (例: Cilium の NodePort) の限界」と「バックエンドの TCP スタックの限界」を切り分けられます。

## 制約と注意

- 送信元 IP は `--device` (または VLAN サブインターフェース) に付いている必要があります。ARP/NDP への応答はカーネルに任せます。
- VLAN 指定時、受信側 NIC の rx-vlan-offload (や veth の hwaccel) でタグが剥がされた応答フレームも受け付け、返す ACK にはタグを押し戻します。
- veth の対向では、live frames から作られた skb にフローハッシュが付かないため、全フローが GRO の同じバケットに入る。1 バケットに保持できるのは 8 フロー (`MAX_GRO_SKBS`) までなので、`--tcp-ip-id flow` でも 9 フロー以上はまとめられない (kind で 8 フローは 8 セグメント/skb、9 フローは 1)。RSS でハッシュが付く実 NIC ではこの制限は無い。
- 単独の `--tcp` では `--rx-device` の分離、IPv6 拡張ヘッダ、QinQ、双方向データには未対応です。`--tcp-server` もサーバからのデータ送信 (固定レスポンス) には未対応です。
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
`--tcp` は併記しません。
使い方と設定項目は [混合送信ガイド](mixed_variants.md)、配分の設計は [混合バリアントの設計](design_mixed_variants.md)、動作確認は [E2E サンプル](../../examples/mixed/test.sh) を参照してください。
混合モードは QinQ と各種トンネル、Timestamps、繰り返しペイロード、フロー別送信元 IP に対応しています。
上記の全ゼロペイロードと Timestamps なしという説明は、単独の `--tcp` に適用されます。
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
