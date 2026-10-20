
## CLI Options Reference

### Commands

```shell
xdperf <command> [options]
```

| Command | Alias | Description |
|---------|-------|-------------|
| `run` | `r` | Run the traffic generator (send or receive mode) |
| `probe` | `p` | Probe XDP capabilities of a network device |

### Probe Command Options

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--device` | `-d` | **Yes** | - | Network interface name to probe |
| `--json` | `-j` | No | `false` | Output results in JSON format |

### Run Command - Operating Modes

For packet traffic, `xdperf run` uses the modes below. Standalone `--tcp`,
`--tcp-server`, and plugin-driven mixed traffic have additional rules described
in [TCP and mixed modes](#tcp-and-mixed-modes).

| Mode | Flags | Description |
|------|-------|-------------|
| **Client Mode** | `--send=true` (default) | Send packets using WASM plugin |
| **Server Mode** | `--send=false --recv=true` | Receive and count packets |
| **Both Mode** | `--send=true --recv=true` | Send packets and count received packets |

**Client Mode** loads a WASM plugin to generate packet templates, writes them to eBPF maps, and transmits packets via XDP. Supports PPS rate limiting and parallel execution.

**Server Mode** attaches an XDP program to the NIC to count incoming packets. With `--swap-resp`, it acts as an echo server (swaps MAC/IP and sends back). No plugin required.

| `--send` | `--recv` | `--swap-resp` | Behavior |
|----------|----------|---------------|----------|
| true | false | - | Send only (default) |
| true | true | false | Send + count received |
| true | true | true | Send + echo received |
| false | true | false | Count received only |
| false | true | true | Echo server |

### Option Reference

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--device` | `-d` | **Yes** | - | Network interface name (e.g., `eth0`, `ens4`) |
| `--rx-device` | - | No | same as TX | Packet client only: count on another device; implies `--recv` |
| `--xdp-mode` | - | No | `auto` | Attach mode: `auto` (fallback to generic), `native`, or `generic` |
| `--wasm-cache-dir` | - | No | user cache + `xdperf/wasm` | WASM compilation cache directory |
| `--count` | `-c` | *Conditional* | - | Number of packets to send (e.g., `1000`, `100k`, `1m`) |
| `--duration` | `-t` | *Conditional* | - | Duration to send packets (e.g., `10s`, `1m`, `500ms`) |
| `--pps` | - | No | unlimited | Target packets per second (e.g., `100k`, `1m`) |
| `--parallelism` | `-l` | No | `1` | Number of parallel sending threads |
| `--cpu-mode` | - | No | `auto` | NUMA-aware CPU pinning: `auto`, `local`, `balanced`, `node:<N>`, or a CPU list (e.g., `0,2,4,6`) |
| `--send` | `-s` | No | `true` | Run in send mode |
| `--recv` | `-r` | No | `false` | Run in receive mode |
| `--swap-resp` | `--swap` | No | `false` | Swap response packets (for echo server) |
| `--show-nic-stats` | - | No | `false` | Show NIC-level statistics |
| `--plugin` | `-p` | No | `simpleudp.tinygo` | Plugin name in format `<name>.<language>` |
| `--plugin-path` | `-P` | No | `/usr/local/share/xdperf/plugins` | Directory containing plugin files |
| `--plugin-language` | `-L` | No | (auto-detected) | Plugin language (`go`, `tinygo`, or `c`) |
| `--plugin-config` | `--cfg` | No | - | Plugin configuration in JSON format |
| `--plugin-config-path` | `--cfgpath` | No | - | Path to JSON configuration file |
| `--debugmode` | `-D` | No | `0` | Debug level (0: off, 1: on, 2: verbose) |
| `--infinite` | - | No | `false` | Enable infinite mode for maximum throughput |
| `--batch-size` | - | No | `64` | Syscall batch size tuning |
| `--otlp-endpoint` | - | No | - | OTLP gRPC endpoint (`host:port`) to export metrics. Empty to disable |
| `--otlp-interval` | - | No | `10s` | OTLP metrics export interval |
| `--otlp-insecure` | - | No | `false` | Use insecure (plaintext) gRPC connection for OTLP export |
| `--otlp-attributes` | - | No | - | Additional OTLP resource attributes (`key=value,key=value`) |

### TCP and Mixed Modes

`--tcp` uses CLI settings and no plugin. `--tcp-server` receives without a
plugin or TX workers. A plugin response containing `kind: "tcp_flow"` selects
mixed mode without `--tcp`; at least one `packet` variant is also required.

| Option | Default | Meaning |
|--------|---------|---------|
| `--tcp` | `false` | Standalone TCP sender; implies `--send` |
| `--tcp-dst` | required for `--tcp` | Destination IP literal and port (`[v6]:port` for IPv6) |
| `--tcp-src-ip` | route preferred source | Source IP on the device |
| `--tcp-dst-mac` | ARP/NDP | Next-hop MAC override |
| `--tcp-flows` | `1` | Concurrent flows; 1..65536, within source-port capacity |
| `--tcp-port-base` | `10000` | First source port; base + flow count must be <= 65536 |
| `--tcp-window` | `32` | Maximum in-flight segments per flow, 1..65535 |
| `--tcp-mss` | MTU-sized, 1448 IPv4 / 1428 IPv6 | Payload size, minimum 64; extra headers/options reduce the default |
| `--tcp-bytes` | `0` | Bytes per flow (`k`/`m`/`g`); zero requires duration |
| `--tcp-rto` | `200ms` | Retransmission timeout |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | `0` / `0` | VLAN ID (0 = no tag) and priority |
| `--tcp-ip-id` | `flow` | Per-flow IPv4 ID, or `shared` per TX CPU |
| `--tcp-flow-report` | disabled | CSV path for each TCP flow’s final ledger in standalone or mixed mode |
| `--tcp-server` | `false` | XDP responder; implies receive-only mode |
| `--tcp-listen` | `:5201` | Responder address; omitted IP = any IPv4, `[::]:port` = any IPv6 |
| `--tcp-max-conns` | `262144` | Responder LRU flow-table size |
| `--tcp-sweep-after` | `max(65*rto, 2s)` | Retire idle SYN_RCVD/LAST_ACK entries |
| `--tcp-ack-every` | `1` | ACK every N in-order data segments (1..255); PSH/FIN/out-of-order get immediate ACKs |

Standalone TCP needs `--tcp-bytes` and/or `--duration`, accepts duration without
PPS, and rejects `--plugin`, `--recv`, `--count`, `--infinite`, and `--rx-device`.
The responder accepts duration without PPS and rejects `--tcp`, `--swap-resp`,
`--rx-device`, `--count`, and `--infinite`.

Mixed mode retains the plugin CLI rule: choose count, or duration with PPS.
Here count sizes the packet diff pool; it does not limit transmitted frames.
PPS limits TX iterations, including TCP iterations that send nothing.
Mixed mode rejects `--infinite`, `--rx-device`, and `--swap-resp`.
The plugin supplies destinations, flow counts, and byte targets; do not set
`--tcp-dst`, `--tcp-flows`, or `--tcp-bytes` for mixed traffic.
Use `--recv` to count packet replies; TCP replies are always processed.

The CSV columns are `flow,src_port,state,tx_pkts,tx_data,tx_rtx,rx_pkts,rx_replies,bytes_acked`.
`tx_pkts + rx_replies` counts frames handed to XDP_TX, before any downstream
loss; `tx_data + tx_rtx` counts data segments including retransmissions.
UDP is absent from this ledger. See the [TCP guide](ja/tcp_stream.md) for details.

See the [mixed-traffic guide](ja/mixed_variants.md) for `base_packet`,
encapsulation, timestamps, payload patterns, and per-flow variable parameters.
It also describes deferred BPF loading and startup costs.
The [RX diagnostic table](ja/tcp_stream.md#混合モードの-rx-診断) explains the
`rx_parse_failed`, `rx_port_outside`, `rx_tuple_mismatch`, `rx_neighbor`,
`rx_other`, and `rx_invalid_tcp` counters; these are classifications, not a
measurement of lost replies.

### Option Details

The count/duration/PPS constraints below apply to the plugin packet and mixed
sender modes. Receive-only and standalone TCP modes use the rules above.

#### `--device`, `-d` (Required)

Specifies the network interface to send packets through.

```shell
sudo xdperf run --device eth0 --count 1000
```

#### `--count`, `-c` / `--duration`, `-t`

Specify how many packets to send. You must use **either** `--count` **or** `--duration`, but not both.

**`--count`**: Total number of packets to send. Supports suffixes:
- `k` = 1,000 (e.g., `100k` = 100,000)
- `m` = 1,000,000 (e.g., `1m` = 1,000,000)

**Note**: When `--infinite` is set, `--count` specifies the number of packet pools (packet templates) instead of total packets to send.

```shell
# Send 100,000 packets
sudo xdperf run --device eth0 --count 100k

# Send 1 million packets
sudo xdperf run --device eth0 --count 1m

# Infinite mode: 10k packet pools, send continuously until Ctrl-C
sudo xdperf run --device eth0 --count 10k --infinite
```

**`--duration`**: Duration to send packets. Uses Go duration format (e.g., `10s`, `1m`, `500ms`).

**Note**: `--duration` requires `--pps` to be specified.

```shell
# Send packets at 100k pps for 10 seconds
sudo xdperf run --device eth0 --duration 10s --pps 100k
```

**Constraint: `--count` and `--duration` cannot be used together.**

```shell
# Error: cannot specify both --count and --duration
sudo xdperf run --device eth0 --count 1000 --duration 10s
```

#### `--pps`

Target packets per second. Supports the same suffixes as `--count` (`k`, `m`).
If not specified, packets are sent at maximum speed.

**Note:** `--pps` cannot be used alone. It must be combined with `--count` or `--duration`.

```shell
# Send at 50,000 packets per second
sudo xdperf run --device eth0 --count 1m --pps 50k

# Maximum speed (no rate limit)
sudo xdperf run --device eth0 --count 1m

# Error: --pps alone is not allowed
sudo xdperf run --device eth0 --pps 100k  # requires --count or --duration
```

#### `--parallelism`, `-l`

Number of parallel threads for packet sending. Each thread is pinned to a separate CPU core.

**Constraints:**
- Must be a positive integer
- Cannot exceed the number of available CPU cores
- `--count` must be greater than or equal to `--parallelism`

```shell
# Use 4 parallel threads
sudo xdperf run --device eth0 --count 100k --parallelism 4
```

**Invalid examples:**
```shell
# Error: parallelism exceeds CPU count (on 8-core machine)
sudo xdperf run --device eth0 --count 100k --parallelism 16

# Error: count must be >= parallelism
sudo xdperf run --device eth0 --count 5 --parallelism 10
```

#### `--cpu-mode`

Controls which CPU cores the parallel sending threads are pinned to. By default (`auto`), xdperf detects the NIC's NUMA node and pins worker threads to CPUs on that node, reducing cross-node memory access on multi-socket servers.

For every mode **except an explicit CPU list**, the number of CPUs selected is governed by `--parallelism`.

| Mode | Behavior |
|------|----------|
| `auto` (default) | Pin to the NIC's local NUMA node first; if `--parallelism` exceeds the local CPUs, spill over to other nodes. |
| `local` | Pin **only** to the NIC's local NUMA node. Errors if `--parallelism` exceeds the CPUs on that node. |
| `balanced` | Distribute threads round-robin across all NUMA nodes. |
| `node:<N>` | Pin to CPUs on NUMA node `N` (e.g., `node:1`). Errors if the node does not exist or has too few CPUs. |
| `<cpu list>` | Pin to an explicit set of CPUs in Linux cpulist format (e.g., `0,2,4,6` or `8-15`). **This overrides `--parallelism`** — the thread count becomes the number of CPUs listed. |

**Note:** On single-node (non-NUMA) systems, or when the NIC reports no NUMA affinity (`numa_node` = `-1`), `auto` and `local` fall back to the first `--parallelism` CPUs.

**Finding the NIC's NUMA node:**

```shell
# NUMA node the NIC is attached to (-1 means no affinity / single-node system)
cat /sys/class/net/eth0/device/numa_node

# CPUs belonging to each NUMA node
lscpu | grep NUMA
# or
numactl --hardware
```

**Examples:**

```shell
# Auto (default): pin to the NIC's local node
sudo xdperf run --device eth0 --count 10k --parallelism 8 --infinite

# Force NIC-local node only (fails fast if the node has fewer than 8 CPUs)
sudo xdperf run --device eth0 --count 10k --parallelism 8 --infinite --cpu-mode local

# Pin to a specific NUMA node
sudo xdperf run --device eth0 --count 10k --parallelism 8 --infinite --cpu-mode node:1

# Explicit CPU list: parallelism is taken from the list (4 threads on CPUs 8,10,12,14)
sudo xdperf run --device eth0 --count 10k --infinite --cpu-mode 8,10,12,14

# Spread evenly across all nodes
sudo xdperf run --device eth0 --count 10k --parallelism 16 --infinite --cpu-mode balanced
```

#### `--send`, `-s` / `--recv`, `-r`

Control send and receive modes. By default, `--send` is enabled and `--recv` is disabled.

| Mode | `--send` | `--recv` | Description |
|------|----------|----------|-------------|
| Send only | `true` (default) | `false` (default) | Send packets only |
| Send + Receive | `true` | `true` | Send packets and measure received packets |
| Receive only | `false` | `true` | Server mode - receive and measure incoming traffic |

```shell
# Send only (default)
sudo xdperf run --device eth0 --count 1m

# Send and receive
sudo xdperf run --device eth0 --count 1m --recv

# Receive only (server mode)
sudo xdperf run --device eth0 --send=false --recv
```

#### `--swap-resp`, `--swap`

When enabled, swap source and destination in response packets. Useful for echo server scenarios.

```shell
sudo xdperf run --device eth0 --send=false --recv --swap-resp
```

#### `--plugin`, `-p`

Plugin name must follow the format `<name>.<language>`.

| Format | Description |
|--------|-------------|
| `simpleudp.tinygo` | TinyGo-based plugin (default, smaller binary) |
| `simpleudp.go` | Standard Go-based plugin |
| `mixed.go` | Go plugin mixing packet and TCP flow variants |
| `vxlan.c` | Freestanding C plugin using the TinyGo-style buffer ABI |

```shell
# Using TinyGo plugin (default)
sudo xdperf run --device eth0 --count 1000 --plugin simpleudp.tinygo

# Using Go plugin
sudo xdperf run --device eth0 --count 1000 --plugin simpleudp.go
```

#### `--plugin-language`, `-L`

Explicitly specify the plugin language. If omitted, it is automatically detected from the plugin name suffix.

The host uses the Go adapter for `go` and the buffer ABI for other languages,
including `tinygo` and `c`. An explicit flag is only needed when the name does
not identify the language or when overriding it.

```shell
# Explicit language specification
sudo xdperf run --device eth0 --count 1000 --plugin myplug --plugin-language go
```

#### `--plugin-config`, `--cfg`

Pass plugin configuration as a JSON string. The available parameters depend on the plugin.

For plugin-specific configuration options, see [Plugin Development Guide](../plugins/README.md#simpleudp-plugin-configuration).

#### `--plugin-config-path`, `--cfgpath`

Load plugin configuration from a JSON file.

```shell
# config.json:
# {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 9999}

sudo xdperf run --device eth0 --count 1m --cfgpath ./config.json
```

**Note:** If both `--plugin-config` and `--plugin-config-path` are specified, `--plugin-config` takes precedence.

#### `--show-nic-stats`

Display NIC-level statistics during execution. Note that these statistics may include other traffic on the same interface.

```shell
sudo xdperf run --device eth0 --count 1m --show-nic-stats
```

#### `--debugmode`, `-D`

Set debug output level.

| Level | Description |
|-------|-------------|
| `0` | Debug output disabled (default) |
| `1` | Debug logging enabled |

```shell
sudo xdperf run --device eth0 --count 100 --debugmode 1
```

#### `--infinite`

Enable infinite mode for maximum throughput. In this mode, packets are sent continuously at maximum speed until interrupted with Ctrl-C.

**Constraints:**
- Requires `--send` mode (enabled by default)
- Requires `--count` to specify the packet pool size
- Cannot be used with `--duration`
- `--pps` is ignored (always runs at max speed)

```shell
# Infinite mode with 10k packet pool and 4 parallel threads
sudo xdperf run --device eth0 --count 10k --parallelism 4 --infinite

# High-performance infinite mode with batch optimization
sudo xdperf run --device eth0 --count 10k --parallelism 8 --infinite --batch-size 64
```

#### `--batch-size`

Tune the syscall batch size for `bpf_prog_run` (applies to infinite and
max-speed modes; PPS-limited mode always uses 1). Higher values reduce syscall
overhead but may increase latency.

| Value | Description |
|-------|-------------|
| `64` | Default; tuned for high throughput |
| `1` | One packet per syscall (lowest latency, much lower pps) |

```shell
# Use batch size of 64 for improved performance
sudo xdperf run --device eth0 --count 1m --batch-size 64

# Combined with infinite mode for maximum throughput
sudo xdperf run --device eth0 --count 10k --infinite --batch-size 64 --parallelism 8
```

#### `--otlp-endpoint` / `--otlp-interval` / `--otlp-insecure` / `--otlp-attributes`

Export runtime statistics to an OpenTelemetry Collector over OTLP/gRPC.
Setting `--otlp-endpoint` opts in; without it, no OTel SDK code runs and
behavior is identical to previous versions. Export runs in both send and
receive mode, and the final cumulative values are flushed on shutdown.

Exported metrics (all monotonic cumulative sums; compute rates on the
backend, e.g. with PromQL `rate()`):

| Metric | Unit | Attributes | Source |
|--------|------|------------|--------|
| `xdperf.packets` | `{packet}` | `network.io.direction` = `transmit` / `receive` | XDP TX/RX stats maps |
| `xdperf.bytes` | `By` | `network.io.direction` = `transmit` / `receive` | XDP TX/RX stats maps |
| `xdperf.errors` | `{error}` | `error.type` = `diff` / `checksum` | XDP TX stats map |
| `xdperf.mixed.rx` | `{packet}` | `reason` = `parse_failed`, `port_outside`, `tuple_mismatch`, `neighbor`, `other`, `invalid_tcp` | Mixed RX diagnostics; registered only after mixed mode is selected |
| `xdperf.nic.packets` | `{packet}` | `network.io.direction` = `transmit` | `/sys/class/net/<dev>/statistics/tx_packets` |
| `xdperf.nic.dropped` | `{packet}` | `network.io.direction` = `transmit` | `/sys/class/net/<dev>/statistics/tx_dropped` |

`xdperf.packets`, `xdperf.bytes`, and `xdperf.errors` read the packet-engine
maps; they do not include the TCP engine’s frames or ACKed bytes.

NIC metrics may include other traffic on the same interface (same caveat as
`--show-nic-stats`). Resource attributes include `service.name=xdperf`,
`service.version`, `host.name`, `network.interface.name`, and
`xdperf.mode` (`client` / `server` / `both`), plus anything passed via
`--otlp-attributes`.

An unreachable collector never blocks traffic generation: the exporter dials
lazily, export failures are logged as warnings and retried on the next
interval, and shutdown flush is bounded by a 5s timeout.

```shell
# Export metrics every 10s to a local collector (plaintext gRPC)
sudo xdperf run --device eth0 --count 1m \
  --otlp-endpoint localhost:4317 --otlp-insecure

# Tag a benchmark run for later lookup in Grafana
sudo xdperf run --device eth0 --duration 60s --pps 1m \
  --otlp-endpoint collector.example.com:4317 \
  --otlp-interval 5s --otlp-attributes test.run.id=run42,site=lab1
```

Quick local collector for testing (prints received metrics to its log):

```shell
docker run --rm --network host \
  -v $(pwd)/otelcol.yaml:/etc/otelcol/config.yaml \
  otel/opentelemetry-collector:latest
```

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

#### Capturing transmitted packets (xdp-ninja)

`xdperf run` transmits via XDP and does not write a pcap itself. Capture the
generated traffic with [xdp-ninja](https://github.com/takehaya/xdp-ninja), an
XDP-time capture tool that attaches non-invasively (no changes to, and no
runtime cost in, xdperf) and — unlike tcpdump's cBPF — can walk into
encapsulated inner headers such as GTP-U, VXLAN, MPLS and SRv6:

```shell
# While `xdperf run` is sending on eth0, in another terminal:
sudo xdp-ninja -i eth0 -w capture.pcap

# Or pipe straight into tcpdump, filtering on the inner GTP-U headers:
sudo xdp-ninja -i eth0 "eth/ipv4/udp/gtp/ipv4/udp" | tcpdump -n -r -
```

See the [xdp-ninja README](https://github.com/takehaya/xdp-ninja) for the full
DSL filter syntax and capture modes.

### Option Constraints Summary

These are plugin-sender constraints; TCP and responder exceptions are listed
in [TCP and mixed modes](#tcp-and-mixed-modes).

| Constraint | Description |
|------------|-------------|
| `--device` is required | Must specify a valid network interface |
| `--count` or `--duration` | One of these must be specified (but not both), unless `--infinite` is used |
| `--duration` requires `--pps` | Duration mode needs a rate limit to calculate packet count |
| `--pps` requires `--count` or `--duration` | Cannot be used alone |
| `--count` >= `--parallelism` | Total packets must be at least equal to thread count |
| `--parallelism` <= CPU cores | Cannot exceed available CPU cores |
| `--cpu-mode local`/`node:<N>` fits the node | `--parallelism` must not exceed the CPUs on the target NUMA node |
| `--cpu-mode <cpu list>` overrides `--parallelism` | Thread count is taken from the listed CPUs |
| Plugin name format | Must be `<name>.<language>` unless `--plugin-language` is specified |
| `--infinite` requires `--count` | Packet pool size must be specified |
| `--infinite` cannot use `--duration` | Duration is not applicable in infinite mode |
