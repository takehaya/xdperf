# xdperf

xdperf is a high-performance network traffic generation tool that leverages XDP (eXpress Data Path). It can operate in both client and server modes, enabling measurement of network throughput and packet rate.

In addition, xdperf provides a flexible mechanism for transmitting arbitrary packets. This functionality is implemented through a plugin system based on WASM, which eliminates the dependency issues often encountered with Python-based tools like Trex. Another major advantage is that it does not rely on DPDK.

Furthermore, since xdperf is implemented in Go, it runs as a single binary, making deployment simple and convenient.

## Install

Note: You need to install `jq` beforehand.
```shell
# latest install
curl -fsSL https://raw.githubusercontent.com/takehaya/xdperf/main/scripts/install_xdperf.sh | sudo bash

# extra: select version mode
curl -fsSL https://raw.githubusercontent.com/takehaya/xdperf/main/scripts/install_xdperf.sh | sudo bash -s -- --version v0.5.3
```

## Usage

### Basic Syntax

```shell
sudo xdperf --device <interface> [options]
```

By default, `simpleudp.tinygo` plugin is used (installed at `/usr/local/share/xdperf/plugins`).
For custom plugin development, see [Plugin Development Guide](./plugins/README.md).

### Operating Modes

xdperf has two primary operating modes:

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

### Basic Examples

```shell
# Send 10,000 packets with default settings
sudo xdperf --device eth0 --count 10k

# Send packets for 30 seconds at 100k pps
sudo xdperf --device eth0 --duration 30s --pps 100k
```

### High-Performance Traffic Generation

```shell
# High-throughput: 1M packets with 8 parallel threads at max speed
sudo xdperf --device eth0 --count 1m --parallelism 8

# Rate-limited: 10 seconds at 500k pps with 4 threads
sudo xdperf --device eth0 --duration 10s --pps 500k --parallelism 4
```

### Custom Packet Configuration

```shell
# Small packets for PPS testing
sudo xdperf --device eth0 --count 1m --parallelism 4 \
    --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 64}'

# Large packets for throughput testing
sudo xdperf --device eth0 --count 100k \
    --cfg '{"payload_size": 1400}'
```

### Server Mode (Receive Only)

```shell
# Receive only (server mode)
sudo xdperf --device eth0 --send=false --recv

# Echo server with swap
sudo xdperf --device eth0 --send=false --recv --swap-resp
```

### Development and Debugging

```shell
# Local build with verbose debugging
sudo ./out/bin/xdperf \
    --plugin simpleudp.go \
    --plugin-path ./out/bin \
    --device eth0 \
    --count 100 \
    --debugmode 2

# With NIC statistics
sudo xdperf --device eth0 --count 1m --show-nic-stats
```

## For Developers

The following information describes what is required to build the project.

### Prepare

On a Debian-based Linux environment, make sure the following tools are installed:
* make
* [mise](https://github.com/jdx/mise)
* docker

### Development Setup

```shell
make install-dev-pkg
make install-dev-tools
make install-build-tools

# Used by lefthook (explained later)
make install-lint-tools

# Equivalent to pre-commit
lefthook install
```

### Go Binary Build

```shell
# Development build (includes xdperf binary and plugins)
make build

# Build plugins only
make build-plugins

# Build a specific plugin
make simpleudp.tinygo  # TinyGo version
make simpleudp.go      # Go version

# Build release snapshot with goreleaser
make goreleaser

# Run build test (check for panics)
make test-runnable
```

### BPF Binary Build

```shell
make bpf-gen
# debug pattern
# CEXTRA_FLAGS="-DXDPERF_DEBUG" make bpf-gen
```

## CLI Options Reference

### Option Reference

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--device` | `-d` | **Yes** | - | Network interface name (e.g., `eth0`, `ens4`) |
| `--count` | `-c` | *Conditional* | - | Number of packets to send (e.g., `1000`, `100k`, `1m`) |
| `--duration` | `-t` | *Conditional* | - | Duration to send packets (e.g., `10s`, `1m`, `500ms`) |
| `--pps` | - | No | unlimited | Target packets per second (e.g., `100k`, `1m`) |
| `--parallelism` | `-l` | No | `1` | Number of parallel sending threads |
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

### Option Details

#### `--device`, `-d` (Required)

Specifies the network interface to send packets through.

```shell
sudo xdperf --device eth0 --count 1000
```

#### `--count`, `-c` / `--duration`, `-t`

Specify how many packets to send. You must use **either** `--count` **or** `--duration`, but not both.

**`--count`**: Total number of packets to send. Supports suffixes:
- `k` = 1,000 (e.g., `100k` = 100,000)
- `m` = 1,000,000 (e.g., `1m` = 1,000,000)

```shell
# Send 100,000 packets
sudo xdperf --device eth0 --count 100k

# Send 1 million packets
sudo xdperf --device eth0 --count 1m
```

**`--duration`**: Duration to send packets. Uses Go duration format (e.g., `10s`, `1m`, `500ms`).

**Note**: `--duration` requires `--pps` to be specified.

```shell
# Send packets at 100k pps for 10 seconds
sudo xdperf --device eth0 --duration 10s --pps 100k
```

**Constraint: `--count` and `--duration` cannot be used together.**

```shell
# Error: cannot specify both --count and --duration
sudo xdperf --device eth0 --count 1000 --duration 10s
```

#### `--pps`

Target packets per second. Supports the same suffixes as `--count` (`k`, `m`).
If not specified, packets are sent at maximum speed.

**Note:** `--pps` cannot be used alone. It must be combined with `--count` or `--duration`.

```shell
# Send at 50,000 packets per second
sudo xdperf --device eth0 --count 1m --pps 50k

# Maximum speed (no rate limit)
sudo xdperf --device eth0 --count 1m

# Error: --pps alone is not allowed
sudo xdperf --device eth0 --pps 100k  # requires --count or --duration
```

#### `--parallelism`, `-l`

Number of parallel threads for packet sending. Each thread is pinned to a separate CPU core.

**Constraints:**
- Must be a positive integer
- Cannot exceed the number of available CPU cores
- `--count` must be greater than or equal to `--parallelism`

```shell
# Use 4 parallel threads
sudo xdperf --device eth0 --count 100k --parallelism 4
```

**Invalid examples:**
```shell
# Error: parallelism exceeds CPU count (on 8-core machine)
sudo xdperf --device eth0 --count 100k --parallelism 16

# Error: count must be >= parallelism
sudo xdperf --device eth0 --count 5 --parallelism 10
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
sudo xdperf --device eth0 --count 1m

# Send and receive
sudo xdperf --device eth0 --count 1m --recv

# Receive only (server mode)
sudo xdperf --device eth0 --send=false --recv
```

#### `--swap-resp`, `--swap`

When enabled, swap source and destination in response packets. Useful for echo server scenarios.

```shell
sudo xdperf --device eth0 --send=false --recv --swap-resp
```

#### `--plugin`, `-p`

Plugin name must follow the format `<name>.<language>`.

| Format | Description |
|--------|-------------|
| `simpleudp.tinygo` | TinyGo-based plugin (default, smaller binary) |
| `simpleudp.go` | Standard Go-based plugin |

```shell
# Using TinyGo plugin (default)
sudo xdperf --device eth0 --count 1000 --plugin simpleudp.tinygo

# Using Go plugin
sudo xdperf --device eth0 --count 1000 --plugin simpleudp.go
```

#### `--plugin-language`, `-L`

Explicitly specify the plugin language. If omitted, it is automatically detected from the plugin name suffix.

This option is required because the host runtime handles Go and TinyGo plugins differently (e.g., memory management, initialization sequences). Specifying the correct language ensures proper interaction between the host and the WASM module.

```shell
# Explicit language specification
sudo xdperf --device eth0 --count 1000 --plugin myplug --plugin-language go
```

#### `--plugin-config`, `--cfg`

Pass plugin configuration as a JSON string. The available parameters depend on the plugin.

For plugin-specific configuration options, see [Plugin Development Guide](./plugins/README.md#simpleudp-plugin-configuration).

#### `--plugin-config-path`, `--cfgpath`

Load plugin configuration from a JSON file.

```shell
# config.json:
# {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 9999}

sudo xdperf --device eth0 --count 1m --cfgpath ./config.json
```

**Note:** If both `--plugin-config` and `--plugin-config-path` are specified, `--plugin-config` takes precedence.

#### `--show-nic-stats`

Display NIC-level statistics during execution. Note that these statistics may include other traffic on the same interface.

```shell
sudo xdperf --device eth0 --count 1m --show-nic-stats
```

#### `--debugmode`, `-D`

Set debug output level.

| Level | Description |
|-------|-------------|
| `0` | Debug output disabled (default) |
| `1` | Debug logging enabled |

```shell
sudo xdperf --device eth0 --count 100 --debugmode 2
```

### Option Constraints Summary

| Constraint | Description |
|------------|-------------|
| `--device` is required | Must specify a valid network interface |
| `--count` or `--duration` | One of these must be specified (but not both) |
| `--duration` requires `--pps` | Duration mode needs a rate limit to calculate packet count |
| `--pps` requires `--count` or `--duration` | Cannot be used alone |
| `--count` >= `--parallelism` | Total packets must be at least equal to thread count |
| `--parallelism` <= CPU cores | Cannot exceed available CPU cores |
| Plugin name format | Must be `<name>.<language>` unless `--plugin-language` is specified |
