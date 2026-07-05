# OTLP メトリクス送信ガイド

xdperf は実行中の統計 (送受信パケット数・バイト数・エラー数・NIC カウンタ) を OTLP/gRPC で OpenTelemetry Collector に push できます。ベンチ結果を Prometheus + Grafana などに時系列として残したいときに使います。

英語のフラグリファレンスは [docs/cli.md](../cli.md#--otlp-endpoint----otlp-interval----otlp-insecure----otlp-attributes) を参照してください。

## 有効化

`--otlp-endpoint` を指定したときだけ有効になります。未指定なら OTel SDK は一切初期化されず、従来と同じ動作です。client (送信)・server (受信) の両モードで使えます。

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--otlp-endpoint` | (無効) | OTLP gRPC エンドポイント `host:port` (例 `localhost:4317`) |
| `--otlp-interval` | `10s` | 送信間隔 |
| `--otlp-insecure` | `false` | TLS なし (平文 gRPC) で接続 |
| `--otlp-attributes` | - | 追加リソース属性 `key=value,key=value` |

```shell
# 送信側: 10秒ごとにローカルの Collector へ push
sudo xdperf run --device eth0 --count 1m \
    --otlp-endpoint localhost:4317 --otlp-insecure

# 受信側 (server モード) でも同様に使える
sudo xdperf run --device eth0 --send=false --recv \
    --otlp-endpoint localhost:4317 --otlp-insecure

# ベンチ実行にタグを付けて後から Grafana で絞り込む
sudo xdperf run --device eth0 --duration 60s --pps 1m \
    --otlp-endpoint collector.example.com:4317 \
    --otlp-attributes test.run.id=run42,site=lab1
```

## メトリクス一覧

すべて **累積 (cumulative) の monotonic sum** です。レート (pps / bps) はバックエンド側で計算します (PromQL なら `rate()`)。

| メトリクス | 単位 | 属性 | ソース |
|-----------|------|------|--------|
| `xdperf.packets` | `{packet}` | `network.io.direction` = `transmit` / `receive` | eBPF TX/RX 統計マップ |
| `xdperf.bytes` | `By` | 同上 | 同上 |
| `xdperf.errors` | `{error}` | `error.type` = `diff` / `checksum` | eBPF TX 統計マップ |
| `xdperf.nic.packets` | `{packet}` | `network.io.direction` = `transmit` | `/sys/class/net/<dev>/statistics/tx_packets` |
| `xdperf.nic.dropped` | `{packet}` | 同上 | `/sys/class/net/<dev>/statistics/tx_dropped` |

NIC 系メトリクスは同一インターフェイス上の他トラフィックも含む点に注意してください (`--show-nic-stats` と同じ制約)。

リソース属性: `service.name=xdperf`、`service.version`、`host.name`、`network.interface.name`、`xdperf.mode` (`client` / `server` / `both`)、および `--otlp-attributes` で渡した内容。

## 設計のポイント

- **累積カウンタで送る**: eBPF マップの統計はプロセス生存中リセットされないため、delta 計算をせずそのまま cumulative sum として送ります。前回値の管理が不要になり、値の取りこぼしも起きません。
- **表示系とは独立**: 1 秒ごとの stdout 表示 (`ShowStats`) とは別系統で、OTel SDK の PeriodicReader が `--otlp-interval` ごとにコールバックを呼んで BPF マップを読みます。表示に影響はありません。
- **トラフィック生成をブロックしない**: gRPC 接続は遅延確立 (lazy dial) なので、起動時に Collector が落ちていても送信は始まります。エクスポート失敗は警告ログを出して次の周期にリトライするだけです (同一エラーの連続は Debug に降格してログを埋めません)。
- **終了時に最終値をフラッシュ**: 終了処理で最後の累積値を必ず送ってからプロセスが終わります。フラッシュには 5 秒のタイムアウトがあり、Collector 不達でも終了が固まりません。短時間のベンチでも最終カウントがバックエンドに残ります。

## 動作確認 (debug exporter)

受信内容をログに出すだけの Collector を Docker で立てて確認できます。

```yaml
# otelcol.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [debug]
```

```shell
docker run --rm --network host \
    -v $(pwd)/otelcol.yaml:/etc/otelcol/config.yaml \
    otel/opentelemetry-collector:latest
```

xdperf を `--otlp-endpoint localhost:4317 --otlp-insecure` 付きで実行すると、Collector のログに `xdperf.packets` などが表示されます。

## Prometheus + Grafana に流す

Collector に prometheus exporter を足すと Prometheus から scrape できます。

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  prometheus:
    endpoint: 0.0.0.0:8889
    # リソース属性 (xdperf.mode や --otlp-attributes の内容) をメトリクスの
    # ラベルとして展開する。無効のままだと target_info 側に入り、
    # ラベルでの絞り込みができない
    resource_to_telemetry_conversion:
      enabled: true
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
```

メトリクス名は Prometheus 流儀に変換されます (`xdperf.packets` → `xdperf_packets_total` など)。PromQL の例:

```promql
# 送信 pps
rate(xdperf_packets_total{network_io_direction="transmit"}[30s])

# 送信 bps
rate(xdperf_bytes_total{network_io_direction="transmit"}[30s]) * 8

# diff/checksum エラーの発生
increase(xdperf_errors_total[1m])

# 特定のベンチ実行だけを見る (--otlp-attributes test.run.id=run42 を付けた場合)
rate(xdperf_packets_total{test_run_id="run42"}[30s])
```

## ハマりどころ: veth / netns 環境では経路を分ける

xdperf の受信側 (`xdp_rx`) は届いた IPv4/IPv6 パケットをカウントした上で **XDP_DROP** します (エコーサーバでない限り)。つまり **受信側 xdperf がアタッチされたインターフェイス越しには TCP が一切通らず、Collector にも届きません**。

veth + netns のローカル環境で送信側 netns から Collector (root netns 等) に push したい場合は、計測用 veth とは別に管理用の veth を用意してください。

```
netns: xdperf-tx                      root netns
┌────────────────────┐               ┌──────────────────────────┐
│ xdp-tx (計測用) ────┼── veth ──────┼─ xdp-rx (xdperf recv,    │
│   192.168.100.1    │               │   IPv4/v6 は XDP_DROP)   │
│                    │               │                          │
│ mgmt-tx (管理用) ───┼── veth ──────┼─ mgmt-rx                 │
│   192.168.200.1    │               │   192.168.200.2          │
└────────────────────┘               │  otel collector :4317    │
                                     └──────────────────────────┘
```

送信側は `--otlp-endpoint 192.168.200.2:4317` のように管理用経路のアドレスを指定します。物理 NIC での実測時も同様に、計測対象とは別の管理インターフェイス経由で Collector に届く経路を確保してください。
