
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
| `--cpu-mode` | - | No | `auto` | CPU selection to evaluate the environment checks against (same syntax as `run`) |
| `--parallelism` | `-l` | No | `1` | Worker count to evaluate the environment checks against (same as `run`) |

Besides XDP capabilities, `probe` reports the jitter-relevant environment:
kernel release, sched_ext availability (whether `--scx` can run), RT
throttling, CPU frequency governors of the selected worker CPUs, irqbalance,
`isolcpus`/`nohz_full`/`rcu_nocbs` boot parameters, and whether the device's
IRQ affinity overlaps the worker CPUs. Warnings mark jitter-hostile findings;
`--json` carries the full result under `environment`.

### Run Command - Operating Modes

xdperf run has two primary operating modes:

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
| `--plugin-language` | `-L` | No | (auto-detected) | Plugin language (`go` or `tinygo`) |
| `--plugin-config` | `--cfg` | No | - | Plugin configuration in JSON format |
| `--plugin-config-path` | `--cfgpath` | No | - | Path to JSON configuration file |
| `--debugmode` | `-D` | No | `0` | Debug level (0: off, 1: on, 2: verbose) |
| `--infinite` | - | No | `false` | Enable infinite mode for maximum throughput |
| `--batch-size` | - | No | `64` | Syscall batch size tuning |
| `--sched-policy` | - | No | (normal) | Realtime class for TX worker threads: `fifo` or `rr` |
| `--sched-priority` | - | No | `50` | Realtime priority 1-99, used with `--sched-policy` |
| `--disable-rt-throttling` | - | No | `false` | Set `sched_rt_runtime_us=-1` while running (restored on exit; requires `--sched-policy`) |
| `--batch-interval` | - | No | `100ms` | Target batch interval for `--pps` pacing (smaller = smoother traffic, more wakeups) |
| `--pacing-mode` | - | No | `ticker` | Batch pacing engine for `--pps`: `ticker` or `busy` (spins for µs precision, burns one core) |
| `--scx` | - | No | `false` | Dedicate worker CPUs to xdperf via a sched_ext BPF scheduler (kernel >= 6.13 with `CONFIG_SCHED_EXT`) |
| `--otlp-endpoint` | - | No | - | OTLP gRPC endpoint (`host:port`) to export metrics. Empty to disable |
| `--otlp-interval` | - | No | `10s` | OTLP metrics export interval |
| `--otlp-insecure` | - | No | `false` | Use insecure (plaintext) gRPC connection for OTLP export |
| `--otlp-attributes` | - | No | - | Additional OTLP resource attributes (`key=value,key=value`) |

### Option Details

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

```shell
# Using TinyGo plugin (default)
sudo xdperf run --device eth0 --count 1000 --plugin simpleudp.tinygo

# Using Go plugin
sudo xdperf run --device eth0 --count 1000 --plugin simpleudp.go
```

#### `--plugin-language`, `-L`

Explicitly specify the plugin language. If omitted, it is automatically detected from the plugin name suffix.

This option is required because the host runtime handles Go and TinyGo plugins differently (e.g., memory management, initialization sequences). Specifying the correct language ensures proper interaction between the host and the WASM module.

```shell
# Explicit language specification
sudo xdperf run --device eth0 --count 1000 --plugin myplug --plugin-language go
```

#### `--plugin-config`, `--cfg`

Pass plugin configuration as a JSON string. The available parameters depend on the plugin.

For plugin-specific configuration options, see [Plugin Development Guide](./plugins/README.md#simpleudp-plugin-configuration).

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
| `xdperf.nic.packets` | `{packet}` | `network.io.direction` = `transmit` | `/sys/class/net/<dev>/statistics/tx_packets` |
| `xdperf.nic.dropped` | `{packet}` | `network.io.direction` = `transmit` | `/sys/class/net/<dev>/statistics/tx_dropped` |

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

### Scheduling & Pacing Options (jitter tuning)

These flags all default to the previous behavior; nothing changes unless you
opt in. They exist to reduce TX jitter (batch wakeup error and per-second
rate variance), both reported in the final statistics of every `--pps` run:

```
pacing statistics (batch wakeup error)  {"batches": 999, "p50": "262µs", "p99": "1ms", "max": "902µs"}
rate stability (per-second TX pps)      {"samples": 9, "mean_pps": 1000, "cv_percent": 0, ...}
```

#### `--sched-policy` / `--sched-priority` / `--disable-rt-throttling`

Put the TX worker threads (and only them) into a realtime scheduling class
via `sched_setattr(2)`. Other tasks can then no longer preempt the workers,
which tightens the pacing tail on a busy machine.

Realtime tasks are throttled to `sched_rt_runtime_us` per second by default
(usually 950ms/1s), which injects a periodic stall into 100%-busy workers.
xdperf warns when the throttle is active; `--disable-rt-throttling` lifts it
for the run and restores the previous value on exit (not on SIGKILL). Note
that a throttling-free FIFO worker at 100% CPU can starve percpu kthreads on
its CPU — prefer `--scx` for long max-speed runs.

```shell
xdperf run -d eth0 -c 1m --pps 100k --sched-policy fifo --sched-priority 50 --disable-rt-throttling
```

#### `--batch-interval` / `--pacing-mode`

`--pps` pacing sends one batch per interval (default 100ms). A smaller
interval spreads packets more evenly at the cost of more wakeups and more
`bpf_prog_run` calls. Note that each call has a fixed kernel-side cost
(several ms on some kernels); if the interval is smaller than that cost the
run becomes overrun-bound — visible as a constant `p50` batch wakeup error.
Start at `10ms`–`50ms` and check the pacing statistics.

`--pacing-mode busy` replaces the timer with a spin loop toward absolute
deadlines: microsecond-precision batch starts, at the price of one fully
busy core per worker. Combine with `--sched-policy` or `--scx` so the spin
itself is not preempted.

#### `--scx`

Attaches a sched_ext BPF scheduler (kernel >= 6.13 with
`CONFIG_SCHED_EXT=y`) that dedicates the worker CPUs to xdperf for the
duration of the run: all other tasks are confined to the remaining CPUs, and
tasks that can only run on a worker CPU (percpu kthreads) get bounded 20µs
slices. This is "isolcpus without a reboot" and avoids the RT-throttling and
kthread-starvation pitfalls of `--sched-policy`.

While attached the scheduler manages every normal-class task on the system;
it detaches (and the kernel restores its default scheduler) when the run
ends, and automatically if the process dies. Requires send mode, at least
one non-worker CPU for housekeeping, and no other sched_ext scheduler
running. Mutually exclusive with `--sched-policy`. See
[docs/ja/scx_design.md](ja/scx_design.md) for the design.

```shell
xdperf run -d eth0 -c 10m --pps 1m -l 4 --cpu-mode 2,3,4,5 --scx
```

### Option Constraints Summary

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
| `--sched-policy` / `--scx` / `--pacing-mode busy` require send mode | RX has no worker threads to schedule |
| `--sched-priority` within 1-99 | Checked only when `--sched-policy` is set |
| `--disable-rt-throttling` requires `--sched-policy` | Only realtime classes are throttled |
| `--batch-interval` / `--pacing-mode busy` require `--pps` | They only shape rate-limited pacing |
| `--scx` and `--sched-policy` are mutually exclusive | Realtime workers would bypass the sched_ext scheduler |
| `--scx` needs a spare CPU | At least one non-worker CPU must remain for housekeeping |
