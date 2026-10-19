# 混合モード起動時間の測定値

[設計と結果](../../design_mixed_startup.md)の対応比較に使った測定値。
`initial/` は `8844011`、`second/` は `ae262c4` と main `7b16bbc` の比較である。
`final/` は `ec28839` と同じ main の比較で、基底ロードの変数限定と、ループ上限の一度だけの読込を含む。
初回に検出した非カプセル化 1 worker の性能回帰を含め、全 3 回の各 96 試行を保存する。
比較元と変更後の実行ファイル、WASM プラグイン、sink の SHA-256 は各 `builds.json` を参照する。

- `raw.csv`: 各試行のカウンタ、起動時間、混合 pps と goodput。
- `derived.csv`: packet 専用の定常 pps とその実測区間を追加した値。
- `summary.csv`: 条件・指標ごとの平均、対応差と対応変化率の 95% CI。
- `schedule.json`: 無作為化した実行順。各条件の base/head は隣接する。
- `tcp-startup-raw.json` と `tcp-startup-summary.json`: 別測定の通常 `--tcp` 起動時間。

各条件を 6 ブロックで対応付け、差 `head - base` の平均を計算する。
95% CI は `mean ± 2.570581835636305 * sample_stddev / sqrt(6)` とする（t 分布、自由度 5）。
対応変化率 `100 * (head / base - 1)` も各ブロックで求め、同じ式で集計する。
平均値の比とは区別する。
多重比較補正は行わず、有意差がないことを同等性の証明とは扱わない。

`python3 docs/ja/benchmarks/mixed-startup/verify.py` で、保存した測定値から全データセットの集計を再検証できる。

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

全ログ、各試行のコマンド、環境、BPF 情報、実行時刻、測定・集計スクリプトとバイナリは作業ディレクトリ `/tmp/claude-1000/xdperf-seqA/out/mixbench/` と `out/mixbench2/`、`out/mixbench3/` に保存する。
各ディレクトリの README に実行コマンドを記載した。
このディレクトリにはレビュー用の測定値を収録し、大きな実行ファイルと環境ログは含めない。

`legacy-bytecode.txt` は main と最終版の再配置済み BPF 命令バイト列の比較結果。
packet TX/RX と checksum の 3 段、通常 TCP TX/RX と TCP server RX の SHA-256 が一致した。

`final/programs.csv` は全 96 試行で一致した、条件別・プログラム別のロード後 tag と `bytes_xlated`。
