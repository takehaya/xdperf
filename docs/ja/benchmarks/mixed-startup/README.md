# 混合モード起動時間の集計

[設計と結果](../../design_mixed_startup.md)の対応比較に使った集計。
`initial/` は `8844011`、`second/` は `ae262c4` と main `7b16bbc` の比較である。
`final/` は `ec28839` と同じ main の比較で、基底ロードの変数限定と、ループ上限の一度だけの読込を含む。
初回に検出した非カプセル化 1 worker の性能回帰を含め、全 3 回の各 96 試行を集計した。
リポジトリには各回の `summary.csv` と検算スクリプト `verify.py` を残す。
生ログ、試行ごとの値、実行ファイル、ハッシュ一覧は保存していない。
元の作業ディレクトリは削除済みであり、以下の集計値だけから再検算することはできない。

- `initial/summary.csv`: 初回の条件別、指標別の平均、対応差と対応変化率の 95% CI。
- `second/summary.csv`: 2 回目の同じ集計。
- `final/summary.csv`: 最終版の同じ集計。

各条件を 6 ブロックで対応付け、差 `head - base` の平均を計算する。
95% CI は `mean ± 2.570581835636305 * sample_stddev / sqrt(6)` とする（t 分布、自由度 5）。
対応変化率 `100 * (head / base - 1)` も各ブロックで求め、同じ式で集計する。
平均値の比とは区別する。
多重比較補正は行わず、有意差がないことを同等性の証明とは扱わない。

[verify.py](verify.py) は試行ごとの値から対応差と CI を再計算するコードとして残す。
入力は各回の raw.csv、derived.csv、schedule.json、summary.csv、tcp-startup-raw.json、tcp-startup-summary.json であり、コミット済みの summary.csv だけでは動作しない。
初期、2 回目、最終版それぞれの入力ディレクトリを引数に取り、相対パスはこの README と同じディレクトリを基準に解決する。
絶対パスも指定できるが、現在は当時の入力がなく、再検算できる保存先は案内できない。

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

[initial/summary.csv](initial/summary.csv)、[second/summary.csv](second/summary.csv)、[final/summary.csv](final/summary.csv) が現在残る集計データである。
元の測定スクリプト、コマンド一覧、実行順、環境、BPF 情報、バイナリ、通常 TCP 起動の試行値、命令比較の記録は残っていない。
本文の測定結果は当時の記録として扱い、第三者がこのリポジトリだけから同じ入力を再検証できるとはしない。
