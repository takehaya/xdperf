
## CLI Options Reference

### Commands

```shell
xdperf <command> [options]
```

| Command | Alias | Description |
|---------|-------|-------------|
| `run` | `r` | Run the traffic generator (send or receive mode) |
| `probe` | `p` | Probe XDP capabilities of a network device |

### Environment Variables

Every option defined for `run` and `probe` accepts an environment variable.
Use `XDPERF_` followed by the long option name in uppercase, replacing hyphens with underscores.
Aliases use the same variable as the long option.
Values take precedence in this order: **CLI flag > environment variable > default**.
A required option such as `--device` can be supplied through its environment variable.

| Option | Environment variable | Example value |
|--------|----------------------|---------------|
| `--device`, `-d` | `XDPERF_DEVICE` | `eth0` |
| `--plugin`, `-p` | `XDPERF_PLUGIN` | `simpleudp.go` |
| `--count`, `-c` | `XDPERF_COUNT` | `100k` |
| `--send`, `-s` | `XDPERF_SEND` | `false` |
| `--duration`, `-t` | `XDPERF_DURATION` | `10s` |
| `--tcp-flow-report` | `XDPERF_TCP_FLOW_REPORT` | `flows.csv` |
| `--summary-json` | `XDPERF_SUMMARY_JSON` | `result.json` |
| `--otlp-interval` | `XDPERF_OTLP_INTERVAL` | `5s` |
| `--json`, `-j` (`probe`) | `XDPERF_JSON` | `true` |

Values use the same formats and validation as CLI flags, including count/PPS suffixes and Go durations.
Set booleans to `true` or `false`; a CLI flag such as `--recv=false` overrides an environment value of `true`.
Explicit `--tcp-mss`, `--tcp-rto`, `--tcp-vlan-id`, or `--tcp-vlan-pcp` requires `--tcp-server`, including when supplied through `XDPERF_TCP_*`.
Even explicit zero or default values are rejected without the responder.

```shell
# Set variables in the privileged process so sudo does not filter them out.
sudo env XDPERF_DEVICE=eth0 XDPERF_COUNT=100k xdperf run

# A flag overrides the environment: send 1m packets through eth0.
sudo env XDPERF_DEVICE=eth0 XDPERF_COUNT=100k xdperf run --count 1m
```

Legacy field-based names that differ from this rule (such as `XDPERF_PLUGINNAME`, `XDPERF_PLUGINPATH`, and `XDPERF_SENDER`) are not supported; these values were previously overwritten by CLI defaults.
Use `XDPERF_PLUGIN`, `XDPERF_PLUGIN_PATH`, and `XDPERF_SEND` instead.
Logger-only variables remain supported: `XDPERF_LOGGERCONFIG_JSON`, `XDPERF_LOGGERCONFIG_NOCOLOR`, `XDPERF_LOGGERCONFIG_VERBOSE`, `XDPERF_LOGGERCONFIG_QUIET`, and `XDPERF_LOGGERCONFIG_ADDCALLER`.
All logger settings default to `false` or `0`; `--debugmode` greater than zero sets logger verbosity to `1`.

### Probe Command Options

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--device` | `-d` | **Yes** | - | Network interface name to probe |
| `--json` | `-j` | No | `false` | Output results in JSON format |

On Linux 6.3+, `probe` reads `xdp-features` through the `netdev` generic netlink family.
It does not load or attach BPF programs, reconfigure NIC queues, or send test packets.
Existing XDP program IDs and attachment modes are still reported.

| Result | Feature |
|--------|---------|
| `xdp_driver_mode` | `NETDEV_XDP_ACT_BASIC` |
| `xdp_generic_mode` | Always `true` (kernel generic XDP) |
| `xdp_offload_mode` | `NETDEV_XDP_ACT_HW_OFFLOAD` |
| `live_frame_mode` | `NETDEV_XDP_ACT_NDO_XMIT` |

Live-frame `XDP_TX` uses the device's `ndo_xdp_xmit` callback, as described in the [kernel implementation](https://github.com/torvalds/linux/blob/v6.3/net/bpf/test_run.c#L291-L305).
For veth, `NDO_XMIT` is advertised only when its peer has XDP or GRO enabled.
These results describe advertised capabilities; they do not verify successful packet delivery or BPF permissions.
JSON output adds `xdp_features`, the raw unsigned 64-bit feature mask from the kernel (including zero).
The bit values are BASIC=1, REDIRECT=2, NDO_XMIT=4, XSK_ZEROCOPY=8, HW_OFFLOAD=16, RX_SG=32, and NDO_XMIT_SG=64.

Only when the `netdev` family is absent does `probe` fall back to attaching a temporary pass program in native and generic mode.
Each attach and detach completes synchronously before the next operation; a slow driver can therefore block the command.
This fallback requires root privileges and can reconfigure NIC queues, so use it only on an idle test interface.
Its live-frame check runs an unattached `XDP_DROP` program on loopback: it sends no packets and checks only kernel live-frames API support, not the target device's `ndo_xdp_xmit` capability.
The fallback omits `xdp_features` and cannot detect hardware offload support unless an offloaded program is already attached.
Other netlink errors, including missing feature attributes, are returned without attempting an attach.

### Run Command - Operating Modes

For packet traffic, `xdperf run` uses the modes below.
`--tcp-server` and plugin-driven TCP traffic have additional rules described
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
| `--count` | `-c` | *Conditional* | - | TX worker frame limit (e.g., `1000`, `100k`, `1m`) |
| `--duration` | `-t` | *Conditional* | - | Duration to send packets (e.g., `10s`, `1m`, `500ms`) |
| `--pps` | - | No | unlimited | Target packets per second (e.g., `100k`, `1m`) |
| `--parallelism` | `-l` | No | `1` | Number of parallel sending threads |
| `--cpu-mode` | - | No | `auto` | NUMA-aware CPU pinning: `auto`, `local`, `balanced`, `node:<N>`, or a CPU list (e.g., `0,2,4,6`) |
| `--send` | `-s` | No | `true` | Run in send mode |
| `--recv` | `-r` | No | `false` | Run in receive mode |
| `--swap-resp` | `--swap` | No | `false` | Swap response packets (for echo server) |
| `--show-nic-stats` | - | No | `false` | Show NIC-level statistics |
| `--summary-json` | - | No | disabled | Write final statistics to a JSON file |
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

TCP senders use `--plugin tcpflow.go` or another plugin returning `kind: "tcp_flow"`.
TCP-only sets and mixed packet/TCP sets share the mixed engine.
Standalone `--tcp` and its client flags have been removed.
`--tcp-server` receives without a plugin or TX workers.
See [tcpflow.go settings](../plugins/tcpflow.go/README.md) for window, MSS, RTO, IP ID and source-port defaults.

| Option | Default | Meaning |
|--------|---------|---------|
| `--tcp-flow-report` | disabled | CSV path for each TCP flow’s final ledger |
| `--tcp-server` | `false` | XDP responder; implies receive-only mode |
| `--tcp-listen` | `:5201` | Responder address; omitted IP = any IPv4, `[::]:port` = any IPv6 |
| `--tcp-max-conns` | `262144` | Responder LRU flow-table size |
| `--tcp-sweep-after` | `max(65*rto, 2s)` | Retire idle SYN_RCVD/LAST_ACK entries |
| `--tcp-ack-every` | `1` | ACK every N in-order data segments (1..255); PSH/FIN/out-of-order get immediate ACKs |
| `--tcp-mss` | MTU-sized, 1448 IPv4 / 1428 IPv6 | Responder only: advertised MSS, minimum 64 |
| `--tcp-rto` | `200ms` | Responder only: stale-flow retention timeout basis |
| `--tcp-vlan-id` / `--tcp-vlan-pcp` | `0` / `0` | Responder only: 802.1Q VID and PCP; with a nonzero VID, tag replies even to untagged frames (veth/rx offload). VID 0 passes tagged frames to the kernel |

The responder accepts duration without PPS and rejects `--swap-resp`,
`--rx-device`, `--count`, and `--infinite`.

Mixed mode uses `--count` as a TX worker frame limit across packets and TCP, including SYN, data, FIN, retransmissions, probes, and RST.
RX replies, idle iterations, and build failures do not consume the budget.
The mixed count limit is at most 9223372036854775807.
Closing frames sent during duration/signal drain or abort are outside this count limit.
All TCP flows completing first ends the run below count.
At count, the sender skips drain, lingers for 2×RTO, and warns about unfinished flows; the exit status is 0 unless a flow failed.
Finite TCP-only sets need neither count nor duration, and TCP-only duration needs no PPS.
A zero-byte (unlimited) flow requires count or duration.
Sets containing packets require count or duration, and PPS with duration.
PPS limits TX iterations, including TCP iterations that send nothing.
Mixed mode rejects `--infinite`, `--rx-device`, and `--swap-resp`.
The packet Diff pool remains `min(count, 131072 × parallelism)` and count must be at least parallelism when specified.
The plugin supplies destinations, flow counts, byte targets and TCP tuning settings.
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
sender modes. Receive-only and TCP-only modes use the rules above.

#### `--device`, `-d` (Required)

Specifies the network interface to send packets through.

```shell
sudo xdperf run --device eth0 --count 1000
```

#### `--count`, `-c` / `--duration`, `-t`

Specify a frame limit or duration; explicit `--count` and `--duration` cannot be combined.
Finite TCP-only sets can omit both; sets containing packets require one.

**`--count`**: Total TX worker frame limit (mixed TCP may finish earlier). Supports suffixes:
- `k` = 1,000 (e.g., `100k` = 100,000)
- `m` = 1,000,000 (e.g., `1m` = 1,000,000)

**Note**: When `--infinite` is set, `--count` specifies the number of packet pools (packet templates) instead of total packets to send.

For finite packet mode, the total is preserved across workers and PPS batches, including any remainder in the final batch.
This count guarantee applies when no signals are delivered during transmission.
If a signal interrupts a BPF run, the underlying library may retry the batch after sending some packets, exceeding the requested count; cancellation can also stop transmission before the budget is exhausted.
Mixed TCP enforces the frame budget in BPF, including batch retries. Duration/signal drain and abort can send closing frames outside the budget (see above).

```shell
# Send 100,000 packets
sudo xdperf run --device eth0 --count 100k

# Send 1 million packets
sudo xdperf run --device eth0 --count 1m

# Infinite mode: 10k packet pools, send continuously until Ctrl-C
sudo xdperf run --device eth0 --count 10k --infinite
```

**`--duration`**: Duration to send packets. Uses Go duration format (e.g., `10s`, `1m`, `500ms`).

**Note**: `--duration` requires `--pps` when the set contains packet variants.
TCP-only duration works without PPS.
When PPS is supplied, the CLI still derives count from duration and PPS; mixed mode also enforces that frame limit.

In packet mode, the send budget is `floor(PPS × duration in seconds)` packets.
This budget is preserved when it is split across workers and batches.
A budget of zero packets or one exceeding the uint64 range is rejected.

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

**Note:** Sets containing packets require `--count` or `--duration` with `--pps`.
Finite TCP-only sets may use PPS alone to limit TX iterations.

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

#### `--summary-json`

Write one JSON object at shutdown with `--summary-json result.json` (or `XDPERF_SUMMARY_JSON=result.json`).
This works for clients, receive servers, and `--tcp-server`.
The file is overwritten; its parent directory must exist.
`-` is a literal filename, with no stdout shorthand.

```shell
sudo xdperf run --device eth0 --count 10k --summary-json result.json
sudo xdperf run --device eth0 --send=false --recv --summary-json receive.json
sudo xdperf run --device eth0 --tcp-server --duration 10s --summary-json tcp-server.json
```

All counter and rate values are JSON numbers with snake_case keys.
`elapsed_seconds` measures the active run through shutdown (including TCP drain, excluding plugin initialization and JSON file writing).
`tx_packets`, `tx_bytes`, `rx_packets`, `rx_bytes`, `diff_errors`, and `checksum_errors` use the existing packet statistics maps.
`tx_pps`, `rx_pps`, `tx_bps`, and `rx_bps` are their averages over `elapsed_seconds`; bps uses bits per second without a 1024 divisor.
The counters have the same scope as the existing statistics: packet TX excludes TCP flow traffic; mixed RX counts outer UDP packets.
TCP wire byte totals are not measured.

For TCP flow clients, `tcp` contains the final TCP counters, including `flows`, `done`, `failed`, `retransmits`, `window_stalls`, and `data_bytes_sent` (payload bytes).
`mixed` contains the existing dispatch, packet/TCP TX, RX reply, and RX diagnostic counters.
For `--tcp-server`, `tcp_server` contains its final counters, including `accepted`, `closed`, `closed_implicit`, `active`, `bytes` (received payload), and errors; the top-level packet counters and rates are zero because this mode uses a separate statistics map.
`nic` is included when the packet client uses `--show-nic-stats`, with the same interface-wide counters as its final log.
Sections that do not apply are omitted; zero counters within a section are included.

The file is written after successful completion, including handled SIGINT/SIGTERM or context cancellation.
Initialization errors, worker errors, failed TCP flows, and final statistics/report errors skip the JSON output and leave any previous file untouched.
SIGKILL and crashes cannot produce a summary.
A JSON statistics read or file write failure returns a nonzero exit status; a file write failure may leave a partial file.

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
| `--count` or `--duration` | Sets containing packets require one; finite TCP-only sets may omit both; never explicitly combine them |
| `--duration` requires `--pps` | Required for sets containing packets; optional for TCP-only sets |
| `--pps` requires `--count` or `--duration` | Sets containing packets require a run bound |
| `--count` >= `--parallelism` | Total packets must be at least equal to thread count |
| `--parallelism` <= CPU cores | Cannot exceed available CPU cores |
| `--cpu-mode local`/`node:<N>` fits the node | `--parallelism` must not exceed the CPUs on the target NUMA node |
| `--cpu-mode <cpu list>` overrides `--parallelism` | Thread count is taken from the listed CPUs |
| Plugin name format | Must be `<name>.<language>` unless `--plugin-language` is specified |
| `--infinite` requires `--count` | Packet pool size must be specified |
| `--infinite` cannot use `--duration` | Duration is not applicable in infinite mode |
