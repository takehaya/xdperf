# 段階6の Cilium Datapath Plugin 確認データ

2026-10-21 に行った共有 VXLAN 定義の外部観測側との照合データを収録する。
環境、入力のハッシュ、ロード結果、送信条件、キーの格納順、再現手順は [設計書の11.2節](../../design_c_to_go_shared_defs.md#112-段階6の-cilium-datapath-plugin-での確認) を参照する。
性能比較のデータではない。

| ファイル | 内容 |
|---|---|
| [s6dump.py](s6dump.py) | 当時のマップ取得スクリプト。kind ノード名と client の lxc デバイス名を引数に取る |
| [runA.json](runA.json) | Go 版の VNI 100..115 の送信後に取得したダンプ |
| [runBC.json](runBC.json) | Go 版の VNI 200、C 版の VNI 300 の送信後に取得した累積ダンプ。試行 A のキーも含む |

JSON の `entries` の各行は `[送信元IPv4, 宛先IPv4, 送信元ポート, 宛先ポート, VNI, カウンタ]` である。
`target_prog` と `maps` は当時のカーネルの ID であり、再実行時に同じ値になることを期待しない。
`raw_example` は先頭に取得したキーの生バイト列であり、並べ替えた `entries` の先頭に対応するとは限らない。

`runA.json` は16キー、各1,000、計16,000である。
`runBC.json` は VNI 100..115、200、300に分けて読む。
VNI 200と300はそれぞれ256キー、各93または94、計24,000であり、送信元ポート65280..65535の分布も一致する。
どの試行も送信元 `192.168.0.1`、宛先 `192.168.0.2`、宛先ポート5060に一致した。
試行 B と C の `--count 25600` に対して実送信数が24,000なのは、当時の `--pps` のバッチ単位の切り捨てによる。
JSON は観測側のカウンタであり、送信側のログは収録していない。

保存データの照合は、このディレクトリで次のように行える。
ネットワーク操作や xdperf の実行は行わない。

```sh
python3 - <<'PY'
import json
from pathlib import Path

run_a = json.loads(Path("runA.json").read_text())
run_bc = json.loads(Path("runBC.json").read_text())
a = run_a["entries"]
b = [e for e in run_bc["entries"] if e[4] == 200]
c = [e for e in run_bc["entries"] if e[4] == 300]
assert sorted(a) == sorted(e for e in run_bc["entries"] if 100 <= e[4] <= 115)
assert len(run_bc["entries"]) == len(a) + len(b) + len(c)
assert len(a) == 16 and {e[4] for e in a} == set(range(100, 116))
assert all(e[2] == 1024 and e[5] == 1000 for e in a)
for rows in (a, b, c):
    assert all(e[:2] == ["192.168.0.1", "192.168.0.2"] and e[3] == 5060 for e in rows)
    print("VNI", sorted({e[4] for e in rows}), "keys", len(rows), "packets", sum(e[5] for e in rows))
for rows in (b, c):
    assert len(rows) == 256 and {e[2] for e in rows} == set(range(65280, 65536))
    assert {e[5] for e in rows} == {93, 94}
    assert sum(e[5] for e in rows) == 24000
assert sorted((e[2], e[5]) for e in b) == sorted((e[2], e[5]) for e in c)
PY
```

ライブ環境で取得する場合は、ホスト上に Python 3、Docker、`nsenter`、`bpftool` と対象の tracing link を用意し、次の形式で実行する。

```sh
sudo python3 s6dump.py <kind-node-name> <client-lxc-device>
```

スクリプトは `from_container` のプログラムをノードのネットワーク名前空間で特定し、`before` の tracing link が参照する `dpp_vx_flows` を読む。
キーは BTF の配置に合わせて `<IIHHI`、バイト列で返るカウンタはリトルエンディアンの整数として解釈する。
この指定は検証した x86 環境のネイティブ順に対応する。
`bpftool -j` のキーと値が生バイト配列として返る出力を想定しており、整形済みのキーには対応しない。
取得失敗やフック未検出を網羅的に診断する実装ではないため、`target_prog`、`maps`、`entries` が期待する対象を示すことを確認する。

計測用バリアントはリポジトリ外の `~/kindlab/dpp-variants` にあり、ここには収録しない。
ホストの IP を含む `host_*.txt` とバイナリも収録しない。
保存した JSON とスクリプトは、当時の観測結果と解釈方法を残すためのものである。
