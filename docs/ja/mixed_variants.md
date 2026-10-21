# パケットと TCP フローを混合して送信する

`--plugin` で読み込む Wasm プラグインは、パケットと TCP フローを一つの `PacketVariantSet` として返せます。
`--tcp` は付けません。
単独の `--tcp` と `--tcp-server` の使い方は [TCP ストリームガイド](tcp_stream.md) を参照してください。

## サンプルを動かす

```bash
make build
# 対向で TCP シンクを起動する。以下の IP と MAC は実際の環境に合わせる
out/bin/xdperf-sink -listen 192.0.2.2:5201

# 送信側
sudo out/bin/xdperf run --device eth0 --plugin mixed.go --plugin-path out/bin \
  --cfg '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02"}' \
  --count 128 --pps 2000 --tcp-flow-report flows.csv
```

[mixed.go](../../plugins/mixed.go/README.md) は DNS 形式の UDP 問い合わせと 4 本の TCP フローを生成します。
UDP 応答も計測する場合は `--recv` を付け、対向に UDP エコーサーバーを用意します。
TCP の応答は `--recv` の有無によらず処理します。
netns と対向を用意する [mixed の E2E](../../examples/mixed/README.md) でも確認できます。

## SDK の応答を書く

次は `plugin_process` が返す JSON の例です。
CLI の `--cfg` に渡す設定とは異なります。
パケット側は固定の 64 バイト UDP フレーム、TCP 側は固定ヘッダまでの 54 バイトを使います。
アドレスと MAC は例示用です。

```json
{
  "template_type": "variable",
  "variable_packet_template": {
    "pattern": "mixed",
    "variants": [
      {
        "kind": "packet",
        "weight": 3,
        "base_packet": {
          "data": "AgAAAAACAgAAAAABCABFAAAyAABAAEARtrfAAAIBwAACAs8IFOkAHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
          "length": 64
        },
        "variable_params": []
      },
      {
        "kind": "tcp_flow",
        "weight": 1,
        "base_packet": {
          "data": "AgAAAAACAgAAAAABCABFAAAoAABAAD8GAADAAAIBwAACAicQFFEAAAAAAAAAAFAA//8AAAAA",
          "length": 54
        },
        "tcp_flow": {
          "flows": [{"bytes": "65536"}, {"bytes": "262144"}]
        }
      }
    ]
  }
}
```

`kind` の省略または `packet` は従来のパケット生成です。
`base_packet`、`variable_params`、`checksums` を使い、パケットごとの Diff を事前計算します。
`kind: "tcp_flow"` は TCP の状態機械を使い、`tcp_flow.flows` の各要素が接続を表します。
TCP を含む集合は `pattern: "mixed"` に限定します。
packet は省略でき、tcp_flow だけの集合も使えます。
合計で最大 16 バリアントです。
TCP を含む JSON は未知フィールドと重複キーを拒否し、応答全体は 32 MiB 以下に制限します。
従来の packet 専用と raw 応答も引き続き使用できます。

`weight` は正の整数で、合計は uint32 の範囲内に収めます。
重みは worker の TX イテレーションを配分し、TCP が ACK 待ちや完了済みで送れない場合も、その機会を packet へ振り替えません。
したがって 3:1 を指定しても実際の TCP フレーム比率が 25% になるとは限りません。
バイト数や接続数の比率でもありません。
packet 側は有限の重み付き Diff プールを使うため、丸めも生じます。

`flows[].bytes` は uint64 の十進文字列です。
`"65536"` のように指定し、CLI の `1g` のような接尾辞は使えません。
`"0"` は `--duration` 指定時だけ使える無制限フローです。
フロー番号は TCP バリアント順、各 `flows` 配列順に割り当て、送信元ポートは `--tcp-port-base + フロー番号` になります。
全フローでポートを共有せず、ポート範囲は 65535 以下に収めます。

## TCP ひな型と追加フィールドを指定する

| フィールド | 指定と制約 |
| --- | --- |
| `base_packet` | バリアント直下に置く。Ethernet から内側 TCP 固定ヘッダ末尾までのバイト列。`data` は base64、`length` は実際のバイト数と一致させる。TCP オプションやペイロードは含めない |
| `tcp_flow.destination` | IP リテラルとポート。base_packet がなければ必須で、Go が経路と近隣情報からひな型を作る。ひな型があれば省略でき、両方指定した場合は内側宛先との一致が必要。グループごとに異なる宛先も指定できる |
| `tcp_flow.syn_options` / `data_options` | base64 の固定 TCP オプション。MSS と WS はエンジンが SYN に追加する。動的オプションや禁止 kind は拒否し、全体で 40 バイト以下に収める |
| `tcp_flow.encapsulation` | トンネルの内側 L3/L4 オフセットと、外側の長さ、IPv4/UDP チェックサムの修正表。明示的な base_packet が必要 |
| `tcp_flow.timestamps` | `true` で SYN に Timestamps を提示する。合意した相手だけに以後も付け、TSval、TSecr、PAWS はエンジンが管理する。RTO の動的推定は行わない |
| `tcp_flow.payload_pattern` | 最大 256 バイトの base64 列。64 bit のストリーム位置に合わせて繰り返し、再送でも同じ位置の内容を生成する。省略と全ゼロはゼロペイロード経路を使う |
| `variable_params` | tcp_flow の子ではなくバリアント直下に置く。明示的な base_packet が必要。内側送信元 IP のバイト部分範囲だけを、起動時にフローごとに一度評価する |
| `checksums` | TCP バリアントでは使用できない。TCP と IP のチェックサムはエンジンが生成する |

TCP の seq、ack、flags、window、data offset、送信元ポート、長さ、チェックサムはエンジンが更新します。
ひな型の MAC、IP、DSCP、TTL、IPv6 flow label などは保持しますが、ECN は 0 にします。
ひな型を指定した場合、`--tcp-src-ip`、`--tcp-dst-mac`、`--tcp-vlan-id`、`--tcp-vlan-pcp` による上書きは使えません。
固定オプションの上限は通常 SYN 32 バイト、データ 40 バイトで、Timestamps 有効時はそれぞれ 20、28 バイトです。
これらはユーザー指定の固定オプションに使える長さです。
エンジンが付ける Timestamps の 12 バイトと、SYN の MSS/WS の 8 バイトを合わせた TCP オプション全体は 40 バイト以下に収めます。
MSS は追加ヘッダとデータ用オプションを考慮し、有効ペイロードは 64 バイト以上、フレームは MTU と最大フレーム長の範囲内に収めます。

例えば Ethernet 直後に内側 IPv4 がある場合、送信元アドレスをフローごとに変える追加指定は次のようになります。
`AQID` は 3 バイトのパターンです。

```json
{
  "variable_params": [
    {"byte_start": 26, "byte_size": 4,
     "byte_range": {"start": 3221225995, "end": 3221225998},
     "pattern_type": "sequential"}
  ],
  "tcp_flow": {
    "timestamps": true,
    "payload_pattern": "AQID",
    "flows": [{"bytes": "4097"}, {"bytes": "65539"}]
  }
}
```

`byte_start` は Ethernet フレーム先頭からの絶対位置です。
`byte_size` は 1、2、4、6、8、値はネットワークバイト順です。
`sequential` はフロー順に増やして範囲末尾で戻り、`mixed` は起動時にフローごとに抽選します。
セグメントごとには変えません。
範囲の重なり、送信元 IP 以外の変更、unspecified/multicast となるアドレスは拒否します。
フロー別テンプレートの値領域の上限は 64 MiB です。
変更した送信元 IP に応答が戻り、ARP/ND にも答えられるよう、デバイス側のアドレスや経路を用意してください。

## 対応トンネルと制限を確認する

| 形式 | 対応範囲 |
| --- | --- |
| Ethernet / VLAN | タグなし、802.1Q、QinQ。各 Ethernet ヘッダで VLAN は最大 2 段 |
| VXLAN / GENEVE | UDP 宛先 4789 / 6081。GENEVE の可変オプションを解析するが critical オプションは非対応 |
| GRE | version 0、key ありまたはなし、gretap。checksum、routing、sequence は非対応 |
| IPIP | IPv4/IPv6 の組み合わせ。汎用 IPv6 Destination Options には未対応 |
| SRv6 | Routing Type 4 の SRH で内側 IP または Ethernet を包む。TCP 自身の IPv6 ヘッダに SRH が付く形は非対応 |
| GTP-U | GTPv1-U G-PDU。RX は拡張ヘッダを最大 8 個と S/PN を受理する。TX は S/PN を拒否する |
| MPLS | 最大 8 ラベル、bottom-of-stack の直後は IPv4/IPv6。Ethernet を直接包む形式は非対応 |

TX のひな型は内側 TCP 固定ヘッダまでを含めて最大 256 バイト、RX の TCP 先頭は最大オフセット 236 です。
外側 IP は最大 4 層、修正表は長さ 8、外側 IPv4 チェックサム 4、外側 UDP チェックサム 4 までです。
IPv4 オプション、IP 断片、上表以外の IPv6 拡張ヘッダは受理しません。
各上限に加えて全体の長さ制限も適用します。

`encapsulation.lengths` は `constant + 内側 TCP セグメント長` を書く位置を列挙します。
`kind` は `ipv4`、`ipv6`、`udp`、`gtpu` で、外側から内側の解析順に指定します。
`ipv4_checksums` は外側 IPv4 ヘッダ先頭、`udp_checksums[].offset` は外側 UDP ヘッダ先頭です。
外側 UDP の `mode: "zero"` は IPv4 だけ、IPv6 は `"lco"` が必須です。
任意の `udp_source_port` は `base + フロー番号 % count` でフロー別のポートを固定します。
修正表の欠落や構造との不一致はエラーになります。
具体的な修正表は [ひな型設計](design_tcp_flow_template.md#段階-2-の修正表) を参照してください。

RX は内側の IP、TCP ポートで照合し、外側 IP、MAC、VNI、GRE key、TEID、MPLS ラベルは照合条件に含めません。
送信と異なるトンネルや、カプセル化が外れた応答も受理します。
ACK/RST は受信した外側ヘッダのスワップではなく、送信テンプレートから再構築します。
トンネル内の ARP/ND はホストへ渡します。
この対応範囲は混合モードのもので、単独 `--tcp` と `--tcp-server` のトンネル対応を意味しません。
Linux 対向の例は [tcp-vxlan](../../examples/tcp-vxlan/README.md) と [tcp-tunnels](../../examples/tcp-tunnels/README.md) を参照してください。

## 終了条件と起動時間を確認する

`--count` はパケットの Diff プールサイズであり、混合送信の総フレーム数ではありません。
TCP だけの場合は packet 用のベースパケットと Diff を初期化せず、すべての送信機会を TCP に配分します。
`--count` の既定値はなく、TCP だけでも現行 CLI では `--count` または `--duration` が必要です。
有限フローなら `--count 1`（worker が複数なら worker 数以上）を指定でき、この値は TCP の送信量には影響しません。
全 TCP フロー完了、`--duration`、シグナルで終了し、drain 中はパケット送信を止めて TCP を閉じます。
時間指定は `--count` を省き、`--duration` と `--pps` を指定します。
`--infinite`、`--rx-device`、`--swap-resp` は混合モードでは使えません。
宛先、接続数、バイト数はプラグインから渡し、`--tcp-dst`、`--tcp-flows`、`--tcp-bytes` は指定しません。
共通の window、MSS、RTO、送信元ポート先頭、IPv4 ID の方式は TCP フラグで設定できます。

起動時は基底 BPF をロードした後、プラグイン応答を検証し、混合専用の 4 プログラムを追加ロードします。
送信テンプレートから外側ヘッダ修正の上限と LCO の有無を設定し、Timestamps または非ゼロパターンがあれば拡張 TX/RX 入口を選びます。
RX が受理するトンネルは送信形式で限定しません。
Wasm のコンパイルキャッシュがあっても BPF の検証は必要で、パケット専用より起動に時間がかかります。
過去の veth 測定値は [起動時間の設計記録](design_mixed_startup.md) と [段階 4 の測定](design_tcp_flow_template.md#段階-4-の測定記録) にあり、現在の環境での所要時間を保証する値ではありません。

フロー別 CSV は [--tcp-flow-report](tcp_stream.md#フローごとの記録---tcp-flow-report)、受信の分類は [混合 RX 診断](tcp_stream.md#混合モードの-rx-診断) を参照してください。
`rx_parse_failed` などは無関係な通信や未対応形式も含み、損失カウンターではありません。
