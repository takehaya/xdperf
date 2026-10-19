# TCP フローのパケットひな型とカプセル化

## 対象と段階

`PacketVariantSet` の `kind: "tcp_flow"` に、プラグインが生成する Ethernet フレームを渡せるようにする。
[混合バリアント](design_mixed_variants.md)の配分、終了条件、ポート割り当て、送信記録を維持し、[TCP エンジン](design_xdp_tcp.md)の状態機械を共用する。
この文書の API は段階ごとに実装するものであり、後続段階のフィールドを先行して受理しない。

| 段階 | 実装範囲 | ブランチ |
|---|---|---|
| 1 | グループ別 base_packet、Ethernet、VLAN 最大 2 段、IPv4/IPv6、固定 TCP オプション | feat/tcp-flow-template |
| 2 | 256 バイトのひな型、汎用 TX 修正表、VXLAN/GENEVE RX、VXLAN E2E | feat/tcp-flow-encap |
| 3 | SRv6、GTP-U、GRE、IPIP、MPLS の RX | 設計のみ |
| 4 | Timestamps、ペイロードパターン、フロー別 variable_params | 設計のみ |

`--tcp-server` のトンネル対応は対象外とする。
`--tcp` と packet 専用の TX/RX は従来の入口を維持する。
混合集合の packet バリアント必須、pattern=mixed、最大 16 バリアントという条件も維持する。

## フィールドの所有権

エンジンは TCP の seq、ack、flags、window、data offset、送信元ポート、IP/UDP の長さ、チェックサムを更新する。
IPv4 ID は従来の `--tcp-ip-id` に従う。
shared では CPU 別カウンタを使い、per-flow ではひな型の ID を初期値にしてフロー別に増加させる。
TCP の reserved ビットと urgent pointer はひな型から保持するが、URG を含む flags は状態機械が所有する。
ECN 未実装のため、各 IP ヘッダの ECN は 0 にする。
DSCP、TTL、IPv6 traffic class の DSCP 部分と flow label は保持する。
長さとチェックサムの入力値はプレースホルダーとして扱う。
壊れたヘッダ、状態機械に従わない TCP、断片を送りたい場合は packet バリアントを使う。

base_packet を指定した場合はその MAC と IP を使い、経路探索で上書きしない。
送信デバイス、MTU、最大フレーム長は引き続きホストが検査する。
`--tcp-src-ip`、`--tcp-dst-mac`、`--tcp-vlan-*` とひな型の併用は、暗黙の上書きを避けるため拒否する。
base_packet を省略したグループは従来の経路解決とヘッダ生成を使う。

## 段階 1 のプラグイン API

次は混合集合の TCP バリアントだけを抜き出した例である。
`base_packet.data` は SDK の `[]byte` を JSON 化した base64 文字列で、例では Ethernet/IPv4/TCP の最小ヘッダを示す。
長さは実際のバイト数と一致させる。

```json
{
  "kind": "tcp_flow",
  "weight": 1,
  "base_packet": {
    "data": "AgAAAAACAgAAAAABCABFAAAoAABAAD8GAADAAAIBwAACAicQFFEAAAAAAAAAAFAA//8AAAAA",
    "length": 54
  },
  "tcp_flow": {
    "destination": "192.0.2.2:5201",
    "syn_options": "BAIBAQ==",
    "data_options": "AQEBAQ==",
    "flows": [{"bytes": "65536"}, {"bytes": "262144"}]
  }
}
```

destination は base_packet があれば省略できる。
両方指定した場合、内側 TCP の宛先 IP と宛先ポートの一致を検証する。
グループ間で宛先が異なってもよい。
フロー番号と送信元ポートの割り当ては全グループを通じて一意にする。
base_packet は TCP 固定ヘッダまでとし、TCP オプションは専用フィールドに渡す。
TCP data offset の入力は使用せず、生成するオプション長から決める。
IPv4 options、IPv6 拡張ヘッダ、断片、TCP 後方のペイロードを段階 1 では拒否する。
`variable_params` と `checksums` は引き続き拒否する。

`syn_options` と `data_options` も base64 のバイト列である。
ホストは SYN の先頭に従来の MSS(4) + NOP(1) + WS(3、値 7) を追加する。
ユーザー指定の SYN オプションは最大 32 バイト、データ用は最大 40 バイトで、4 バイト境界になるよう末尾を NOP で埋める（EOL 後はゼロで埋める）。
NOP、EOL、SACK-Permitted、実験用オプションなど、セグメントごとに内容が変わらない TLV を保持する。
EOL 以降はゼロのパディングだけを許可する。
不正な TLV 長、重複するエンジン所有の MSS/WS、Timestamps、SACK ブロック、MPTCP、TFO、TCP-AO、TCP-MD5 は拒否する。
Timestamps は段階 4 の専用指定でのみ有効にする。
受信 SACK ブロックは無視し、既存の go-back-N 再送を続ける。

MSS はデバイス MTU とフレーム上限から、L2 の追加タグ、IP、TCP、データ用オプションを引いた上限に収める。
従来の既定 MSS を出発点とし、追加ヘッダ分を減らす。
明示 `--tcp-mss` はオプションを除く基準値として扱い、追加オプション分を差し引く。
SYN の全長も独立に検証する。
相手の広告 MSS からもデータ用オプション分を差し引き、フローの有効 MSS を更新する。
最小有効 MSS は既存の 64 バイトとする。

## BPF マップと送信

既存の `tcp_cfg_map` は全体の flow_count、port_base、drain/abort と従来モードの設定を保持する。
`tcp_template_map` (ARRAY、最大 16) にグループ別の不変設定を格納する。
`tcp_flow` に template_id を追加し、フロー選択後の 1 lookup でグループを得る。
状態機械にはグループ別 MSS と従来の制御設定を渡す。
終了制御を書き換える際はグループ側にも drain/abort を伝える。

段階 1 の値は次を含む。

- `tcp_cfg`：アドレス、ポート、pseudo_sum、MSS、L3/L4 オフセットと既存の再送設定。
- `prefix`：TCP の手前までのバイト列。段階 1 は最大 64 バイト、段階 2 は 256 バイト。
- `tcp_header[20]`：プラグイン所有の固定ビットを保持するための固定ヘッダ。
- `syn_options[40]`、`data_options[40]` と各長さ。

混合 TX は専用 builder で prefix を復元し、TCP ヘッダとオプションを生成する。
混合 packet が残したデータや、以前の SYN オプションを送らないように、一度 TCP 固定ヘッダまで縮小してからゼロで拡張する。
TCP チェックサムはアドレスの事前計算値と生成ヘッダの和から求める。
段階 1/2 のペイロードはゼロであり、ペイロード全体を走査しない。
RX が返す ACK/RST も同じ builder を使う。
これにより QinQ の復元、グループ固有の DSCP/TTL、トンネルへの再カプセル化を TX と共通化する。
RX におけるフロー別 IPv4 ID の採番はフローロック内で行う。

## 段階 2 の修正表

BPF はトンネルの種類に依存せず、prefix と検証済みの修正表を実行する。
Go は既知の構造を解析し、プラグインが指定したオフセット、種類、固定値と照合する。
修正表をホストが暗黙に補完することはしない。
内側 IP の長さとチェックサムはエンジンが常に処理し、表は外側ヘッダを対象とする。
次は Ethernet/IPv4/UDP/VXLAN/Ethernet/IPv4/TCP の例である。
オフセットはフレーム先頭から、segment_len は内側 TCP ヘッダ、オプション、ペイロードの合計と定義する。

```json
{
  "encapsulation": {
    "inner_l3_offset": 64,
    "inner_l4_offset": 84,
    "lengths": [
      {"offset": 16, "kind": "ipv4", "constant": 70},
      {"offset": 38, "kind": "udp", "constant": 50}
    ],
    "ipv4_checksums": [14],
    "udp_checksums": [{"offset": 34, "ip_offset": 14, "mode": "zero"}],
    "udp_source_port": {"offset": 34, "base": 49152, "count": 16384}
  }
}
```

`encapsulation` は `tcp_flow` の子要素とする。
各修正表は外側から内側への解析順に並べ、欠落と重複を拒否する。
lengths の kind は ipv4 (total length)、ipv6 (payload length)、udp、gtpu を区別し、各値はネットワークバイト順の uint16 とする。
実行時は constant + segment_len のオーバーフローを検査する。
udp_source_port は base + flow_index % count を使い、再送や RX 応答でも同じ値にする。
base、count と合計がポート範囲に収まり、指定位置が解析済み外側 UDP の source であることを検証する。

外側 UDP チェックサムは IPv4 のみ zero を許し、IPv6 では lco を必須とする。
LCO は、正しい内側 TCP チェックサムが書かれていることを前提に、内側 TCP 全体の和を TCP 擬似ヘッダ和の補数から求める。
UDP 擬似ヘッダ、UDP ヘッダ、UDP 直後から内側 TCP 手前までのヘッダを加え、ゼロ結果は 0xffff にする。
奇数オフセットではバイトの位相を入れ替える。
UDP が多段の場合は内側から計算し、外側が既に確定した内側チェックサムを参照する。
ペイロード長に比例する走査を避ける。

ひな型上限 256 バイトは TCP 固定ヘッダまでを含む。
最大修正数は長さ 8、IPv4 チェックサム 4、外側 UDP チェックサム 4、解析の入れ子 4 層とする。
Go は VXLAN、GENEVE、GTP-U、SRv6、GRE、IPIP、MPLS の長さと構造を照合する。
未知の構造、IPv4 options、断片、未対応の拡張機能は理由付きで拒否する。
GENEVE の可変オプション長、GTP-U の optional fields、GRE の optional key/sequence、MPLS の bottom-of-stack を解析し、境界を確認する。
対応する送信構造と受信構造が異なる期間は、未対応の RX を利用する設定を明確に説明する。

## 受信側とフロー照合

混合 RX には専用の TCP 解析器を置き、既存 `--tcp` と packet 専用 RX の実行命令を増やさない。
Ethernet と最大 2 段の VLAN を解析し、既知のカプセル化を上限付きで順に外す。
各層の申告長を親層の終端とフレーム終端の両方に照合する。
IP の version、IPv4 IHL、IPv6 next header、断片化、UDP 長、VXLAN I flag、GENEVE version/critical flag/option 長を検査する。
上限超過、未対応の構造、断片はフロー状態を更新せずホストへ渡す。
対象フローと判定した後の不正 TCP 長は DROP する。

内側 TCP の宛先ポートからフロー番号を取り、template_id のアドレスと相手ポートで内側 5 タプル全体を照合する。
外側 IP、VNI、MAC、UDP ポートはフローのキーに含めない。
同じ内側タプルならカプセル化なしの応答も受理する。
送信元ポートは全フローで一意なので、異なるトンネル内のフローも区別できる。
これにより外側の送信経路が非対称でも動作するが、外側属性をセキュリティ境界として検証する用途は対象外である。

段階 2 では VXLAN と GENEVE を外せるようにする。
未一致 UDP は従来の --recv の外側 UDP 計測へ渡し、対象 TCP の RX 応答はグループの送信テンプレートを使って返す。
段階 3 で SRv6 (SRH の長さと segments_left)、GTP-U (G-PDU、拡張ヘッダの上限)、GRE (version/flags)、IPIP、MPLS (ラベル最大数と IPv4/IPv6 判定) を追加する。
これらの解析でも外側のアドレスを照合条件に加えない。

## verifier と古いカーネル

可変オフセットを足したスタックポインタによるアクセスを作らない。
TCP/IP の編集は固定サイズのローカル配列か境界検査済みのパケットポインタで行い、マップ内の prefix は固定オフセットの小ブロックとしてコピーする。
256 バイトの prefix をスタックに全コピーせず、展開したコピー処理でマップからフレームへ書く。
末尾の部分ブロックには定数サイズの書き込みを使う。
すべての可変オフセットに上限を置き、加算前の範囲検査と data_end の検査を併用する。
helper を呼ぶときは bpf_spin_lock を保持しない。

#121 では小さなループも古い verifier の状態数増加を招いたため、コピー、固定長チェックサム、短い VLAN 走査は明示的に展開する。
トンネルの解析は深さに固定上限を置く。
`bpf_loop` の追加依存は作らず、既存 helper の最低要件を維持する。
コンパイル成功だけでは合格にせず、ローカル BPF ロード、BPF_PROG_RUN、CI と既存の vimto カーネル行列を確認する。
拒否された場合は verifier ログから可変スタックアクセスと状態数を調べる。

## 段階 4 の設計

`tcp_flow.timestamps: true` はエンジン生成の TSval/TSecr を有効にする。
SYN でネゴシエーションし、未対応の相手には送らない。
TSval は単調クロックから作り、TSecr は受信した timestamp をフロー状態に保持する。
再送時刻、PAWS、32 bit ラップ、SYN 再送中の値をテストし、オプション長を MSS とチェックサムに反映する。

`tcp_flow.payload_pattern` は最大 256 バイトの base64 列を指定する予定である。
ストリーム開始からの 64 bit オフセットで pattern[index % length] を選ぶ。
再送位置は bytes_acked と seq の差から復元し、4 GiB 超と seq ラップでも同じ中身を生成する。
ゼロパターンには従来の定数時間チェックサムを使い、一般パターンは周期の部分和を事前計算する。

`variable_params` は起動時にフロー単位で評価し、セグメントごとには変化させない。
エンジン所有範囲との重なり、ヘッダ種別や長さの変更を拒否する。
アドレス変更時は擬似ヘッダ和と受信照合情報をフロー単位に保持し、全フローを展開するメモリ上限を別途定める。
MPTCP、TFO、TCP-AO/MD5 はこの段階でも実装せず拒否する。

## 検証と性能

単体テストでは不正な base 長、EtherType、VLAN 深さ、IP version/fragment、宛先不一致、TLV、禁止オプション、MSS 境界、修正表の不足/重複/重なり/範囲外を検証する。
BPF_PROG_RUN では SYN、データ、短い末尾、FIN、再送、RX の ACK を取り出し、Go 側でチェックサムとバイト列を独立に検証する。
2 グループ以上の MAC/IP/DSCP/TTL/オプションが混ざらないこと、QinQ、IPv6 flow label、RX の長さ検証、カプセル化なし応答、UDP LCO とエントロピーを含める。
混合フレームの再利用には非ゼロの入力データを使い、ペイロード汚染を検出する。

veth E2E は sudo で、送信側 xdperf と受信 netns の xdperf-sink を使う。
段階 1 は Ethernet、VLAN、QinQ、IPv4/IPv6 と複数グループを検証する。
段階 2 は Linux vxlan デバイスの内側でカーネル TCP を終端し、accepted/closed、受信バイト、送信 ledger の bytes_acked を照合する。
既存 examples と全 Go テストも実行し、BPF オブジェクト再生成後に検証する。

性能の合格条件は既存の `--tcp` と packet 専用の送受信ホットパスに追加 lookup、コピー、解析を入れないことである。
追加マップのロード時メモリとフロー構造体の増分は別途報告する。
混合 TCP ではグループ lookup、prefix コピー、オプション処理、RX パースの分だけ費用が増える。
命令数と BPF_PROG_RUN の duration を同条件で比較し、実 NIC の PPS/Gbps は測定環境がある場合に記録する。
veth の成功から実 NIC のスループットを推定しない。

## 未解決の論点と実装時の判断

- 未知の固定オプションは TLV と禁止 kind の検査で受理する。未知オプションの意味をホストが保証することはできない。
- 256 バイトと各修正表の上限で表現できない入れ子は拒否する。上限の拡張は verifier と性能の測定後に判断する。
- RX のハードウェア VLAN stripping は復元された送信ひな型で吸収する。外側属性を照合しないため、VLAN の認証機能にはならない。
- LCO は内側チェックサムが有効であることが前提である。段階 4 のペイロード生成を追加する際も、この不変条件を維持する。
- IPv6 拡張ヘッダと SRv6 の TCP 擬似ヘッダ宛先は区別する。SRH 配下の内側 TCP と、SRH が TCP 自身の IPv6 ヘッダに付く形を混同せず、後者は明示的な対応まで拒否する。
- 手元に古いカーネル VM がない場合、CI の検証結果と未実施範囲を PR に明記する。

## 段階 1 の測定記録

clang-22 で生成した BPF 命令数は、packet TX 391、packet RX 176、通常 TCP RX 1126 で変更前と同じだった。
通常 TCP TX は再送統計のコンパイラ生成差により 1086 から 1088 命令になったが、追加 lookup やひな型処理は含まない。
混合 TCP TX は 1117 から 2058 命令、新設の混合 TCP RX は 2221 命令である（命令数はスループットの測定値ではない）。
フローの template_id は既存のアラインメント用空間に置き、tcp_flow_map の値サイズ 120 バイトを維持した。
グループマップの値領域は全 16 エントリで 5120 バイト増える。

## 段階 2 の実装上の判断

段階 2 は汎用 TX、VXLAN/GENEVE RX、Linux VXLAN 相手の IPv4/IPv6 E2E を実装する。
GRE checksum と routing フラグは拒否する。
合意した修正表には GRE checksum の種類がなく、長さ変更後の正しい値を生成できないためである。
key と sequence のバイトは保持し、version 0 の GRE、IPIP、SRv6、GTP-U、MPLS の送信ひな型を解析して照合する。
これらをカプセル化した応答の受信は段階 3 とし、カプセル化なしの応答は段階 2 でも受理する。
SRH は内側 IP または Ethernet を包む形に限定し、TCP/UDP が SRH の直後にある形は擬似ヘッダの宛先が変わるため拒否する。

外側 IPv4 ID は shared モードでは内側と同じ CPU 別採番値に更新し、それ以外ではひな型の値を保持する。
内側 IPv4 ID のフロー別採番は従来どおりである。
固定オプションのチェックサム和は Go で事前計算し、BPF がオプション列を加算する際のレジスタ退避を減らした。
ひな型を 8 バイトずつコピーし、端数が TCP 固定ヘッダへ重なる部分は後からエンジンの TCP ヘッダで上書きする。
これにより 256 バイト全体をスタックに置かずに復元できる。

受信の層走査は最大 5 回（外側 4 層と内側 TCP）を展開する。
GENEVE のオプション検査は別関数で最大 40 回を展開する（256 バイト上限内に実際に入る最小オプションは最大 38 個）。
可変オフセットのパケットポインタをコンパイラが組み替えて境界証明が失われる箇所は、固定サイズの `bpf_xdp_load_bytes` で読む。
外側 IPv4 の編集も固定サイズのローカル配列を使う。
LCO はチェックサム確定済みの内側 UDP から外側へ計算し、TCP ペイロードを走査しない。

## 段階 2 の測定記録

段階 1 と比較すると、packet TX/RX と通常 TCP TX/RX は生成バイトコードが同一だった。
命令数はそれぞれ 391、176、1088、1126 である。
混合 TCP TX は 2058 から 14421 命令、混合 TCP RX は 2221 から 17379 命令になった。
増加分には旧カーネルの verifier 向けに展開した境界検査と LCO 処理が含まれる。
グループマップの値サイズは 320 から 632 バイトとなり、全 16 エントリの値領域は 10112 バイトである。
実 NIC での PPS/Gbps は未測定であり、命令数から混合経路のスループットを推定しない。

全プログラムを通常モードでも検証すると、手元の E2E では受信側の起動が 5 秒の待機上限を超えた。
このため、アプリケーション起動時は混合専用の 4 プログラムを除き、プラグインの応答が混合集合の場合に追加ロードする。
追加ロードは既存マップを再利用し、フロー状態と tail call の参照先を共有する。
カーネル互換性を検査する `ReadCollection` は引き続き全プログラムをロードする。
