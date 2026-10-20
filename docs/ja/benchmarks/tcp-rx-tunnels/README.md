# 受信トンネル解析の対応比較

比較元は `ad72a7f`、変更後は `9277b88` とする。
バイナリとプラグインは Go 1.25.5 でビルドした。
当時の生ログ、実行ファイル、SHA-256 の記録は保存していない。
測定環境は Linux 7.0.0-38-generic、AMD EPYC 7713P を公開する 32 vCPU の KVM VM、Linux veth であり、実 NIC のスループットを示す結果ではない。

既存 mixbench の送受信、タイミング、終了時の照合を継承した。
変更点は全条件で base/head を測ることと、専用の名前空間名を使うことである。
packet 専用、非カプセル化 TCP ひな型、VXLAN、GENEVE の 4 条件を、1/4 worker、6 ブロック、各 8 秒で測定する。
各条件の base/head を隣接させ、ブロック内の条件順と各対の実行順を無作為化する。
混合比は packet:TCP=3:1、TCP は 4 フロー、MSS 1024、window 32 とする。
VXLAN/GENEVE は外側 IPv4/UDP LCO を使う。
統計用 BPF runtime counters は無効とし、測定後に元の設定を復元する。

起動時間はプロセス起動から送信開始ログまでとする。
混合スループットは送信開始から drain 開始までの時間と最終カウンタから求める。
packet 定常 pps は統計ログの最初の 6 区間から求め、終了処理に影響される最終カウンタ pps も残す。
対応差は各ブロックの `head - base`、対応変化率は `100 * (head / base - 1)` の平均である。
両側 95% CI は対応差の標本標準偏差と t 分布（自由度 5、係数 2.570581835636305）で計算する。
多重比較補正や外れ値除外は行わない。

Git に残す測定データは `summary.csv` と検算用の `verify.py`、表を生成する `report.py` だけとする。
結果と解釈は [設計書](../../design_tcp_flow_template.md#段階-3-の測定記録) に記載する。
現在残るのは [summary.csv](summary.csv)、[verify.py](verify.py)、[report.py](report.py) である。
生ログ、試行ごとの raw.csv と derived.csv、実行順の schedule.json、環境、ビルド情報、測定スクリプトは保存していない。
元の作業ディレクトリは削除済みであり、リポジトリ外の一時領域も永続的な保存先として案内しない。

verify.py は入力ディレクトリを第 1 引数として受け取り、96 試行の網羅性、エラー数、バイト数、対応差と CI を検査するコードである。
必要な raw.csv、derived.csv、schedule.json がないため、現在のリポジトリだけでは再検算できない。
report.py はコミット済みの集計から表を生成できる。
これは生データの再検算とは区別する。

```sh
# リポジトリのルートで、残っている summary.csv から表を表示する
python3 docs/ja/benchmarks/tcp-rx-tunnels/report.py
```

## 機能検証

実装コミット `9277b88` に対して `make test`（`go test -v -exec sudo -race ./...`）、`make test-runnable`、`make lint` が成功した。
C WASM プラグインもビルドして integration test を実行した。
最終の既存走査保持とスタック修正を含む状態で全 examples 13 シナリオを再実行し、すべて成功した。
当時の実行ログは保存していない。

新しい tcp-tunnels は内側 IPv4/IPv6 ごとに gre、gre-key、gretap、ip6gre、ipip/SIT、ip6tnl、srv6、srv6-two、srv6-bare、mpls、gtpu を実行する。
全 22 ケースで、実際の Linux デバイスを対向に 4 フロー完了、77,830 バイトの受信と ACK を照合した。
この環境ではスキップも BPF_PROG_RUN のみによる代替もない。
GTP-U 拡張ヘッダ、最大 8 label、SRH と異種入れ子、不正長、全 byte 境界の切詰めなどは BPF_PROG_RUN で追加検証した。

Linux 6.1/6.6 の CI で一度、parser の合計 stack が 544 バイトとなりロードに失敗した。
`9277b88` で legacy walker のフレームを解放してから extended walker を呼ぶ構成へ修正した。
修正後は [BPF load / data-plane CI](https://github.com/takehaya/xdperf/actions/runs/39294979917) の Linux 6.1、6.6、6.12、6.18、7.0、7.1、7.2-rc2 すべてで成功した。
OCR は 4 名による 4 回のレビューを行い、GTP-U の受信規則、環境依存 E2E の扱い、旧新 walker の境界テスト、集計表の完全性検証を修正し、未解消の指摘はない。
