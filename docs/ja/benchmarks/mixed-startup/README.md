# 混合モード起動時間の集計

[設計と結果](../../design_mixed_startup.md)の対応比較に使った集計。
`initial/` は `8844011`、`second/` は `ae262c4` と main `7b16bbc` の比較である。
`final/` は `ec28839` と同じ main の比較で、基底ロードの変数限定と、ループ上限の一度だけの読込を含む。
初回に検出した非カプセル化 1 worker の性能回帰を含め、全 3 回の各 96 試行を集計した。
リポジトリには各回の `summary.csv` と検算スクリプト `verify.py` を残す。
生データと実行ファイルのハッシュ一覧は、後述の git 管理外の保存先で保全する。

- `initial/summary.csv`: 初回の条件別、指標別の平均、対応差と対応変化率の 95% CI。
- `second/summary.csv`: 2 回目の同じ集計。
- `final/summary.csv`: 最終版の同じ集計。

各条件を 6 ブロックで対応付け、差 `head - base` の平均を計算する。
95% CI は `mean ± 2.570581835636305 * sample_stddev / sqrt(6)` とする（t 分布、自由度 5）。
対応変化率 `100 * (head / base - 1)` も各ブロックで求め、同じ式で集計する。
平均値の比とは区別する。
多重比較補正は行わず、有意差がないことを同等性の証明とは扱わない。

検算には git 管理外の生データが必要であり、このリポジトリだけでは再計算できない。
以下の保存先を引数で指定すると、既存の `verify.py` で全データセットの集計、条件の欠落と重複、各条件の 6 対、通常 `--tcp` の起動時間を再検証できる。
リポジトリのルートから実行する。

```sh
python3 docs/ja/benchmarks/mixed-startup/verify.py \
  "$PWD/out/mixed-startup-review-data/initial" \
  "$PWD/out/mixed-startup-review-data/second" \
  "$PWD/out/mixed-startup-review-data/final" || exit 1
for dataset in initial second final; do
  cmp "docs/ja/benchmarks/mixed-startup/$dataset/summary.csv" \
    "out/mixed-startup-review-data/$dataset/summary.csv" || exit 1
done
```

`cmp` で、検算した集計と追跡対象の集計が同一であることも確認する。

既存 mixbench の手順を継承し、全条件を両バージョンで測定した。
6 ブロック、各 8 秒、1／4 worker、packet 専用／非カプセル化／VXLAN／GENEVE、pps 制限なし。
混合比率は packet:TCP = 3:1、TCP は 4 flow、MSS 1024、window 32、各フローの目標は 1 TiB。
VXLAN と GENEVE は外側 IPv4/UDP LCO、VNI 7、内側 Ethernet/IPv4/TCP、GENEVE オプションなし。
packet 専用の定常 pps は最初から 7 回目までの統計ログの 6 区間で計算する。
混合 pps/goodput は送信開始から drain 開始までの時間と最終カウンタで計算する。
最終 ACK 済みバイト数には drain 開始時に送信中の最大 128 KiB が含まれ得る。
全フローの ACK 済みバイト数と sink 受信バイト数、接続数、終了状態を確認する。

ホストは Linux 7.0.0-38-generic、Go 1.25.5、BPF は Docker の clang 22.1.8。
専用 netns と 4 queue veth を使用し、送信プロセスは CPU 4–11、worker は 4 または 4–7、sink は 12–15 に固定した。
乱数 seed は主測定 121123、通常 TCP 起動 20261020。

元の全ログ、各試行のコマンド、環境、BPF 情報、実行時刻、測定と集計のスクリプト、バイナリは作業ディレクトリ `/tmp/claude-1000/xdperf-seqA/` の以下の場所に保存する。

| データセット | 元の測定資料 | 検算用の保全先 |
| --- | --- | --- |
| initial | `out/mixbench/` | `out/mixed-startup-review-data/initial/` |
| second | `out/mixbench2/` | `out/mixed-startup-review-data/second/` |
| final | `out/mixbench3/` | `out/mixed-startup-review-data/final/` |

元の各ディレクトリの README に実行コマンドを記載した。
検算用の保全先には、追跡対象から外す前の `raw.csv`、`derived.csv`、`schedule.json`、`builds.json`、`summary.csv`、`tcp-startup-raw.json`、`tcp-startup-summary.json` を同じ構成で保存した。
`builds.json` には比較元と変更後の実行ファイル、WASM プラグイン、sink の SHA-256 を記録している。
`raw.csv` は各試行のカウンタと起動時間、混合 pps と goodput、`derived.csv` は packet 専用の定常 pps とその実測区間も含む。
`schedule.json` は無作為化した実行順を記録し、各条件の base/head は隣接する。
通常 `--tcp` の別測定は `tcp-startup-raw.json` と `tcp-startup-summary.json` に保存した。
`out/` 全体は git 管理外とする。

`out/mixed-startup-review-data/legacy-bytecode.txt` は main と最終版の再配置済み BPF 命令バイト列の比較結果。
packet TX/RX と checksum の 3 段、通常 TCP TX/RX と TCP server RX の SHA-256 が一致した。

`out/mixed-startup-review-data/final/programs.csv` は全 96 試行で一致した、条件別、プログラム別のロード後 tag と `bytes_xlated`。
