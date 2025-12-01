# XDPerf

<p align="center">
  <img src="./docs/imgs/logo.png" alt="XDPerf image" width="300">
</p>

XDPerf is a high-performance network traffic generation tool that leverages XDP (eXpress Data Path). It can operate in both client and server modes, enabling measurement of network throughput and packet rate.

In addition, XDPerf provides a flexible mechanism for transmitting arbitrary packets. This functionality is implemented through a plugin system based on WASM, which eliminates the dependency issues often encountered with Python-based tools like Trex. Another major advantage is that it does not rely on DPDK.

Furthermore, since XDPerf is implemented in Go, it runs as a single binary, making deployment simple and convenient.

You can find the project explanation slides at [./docs/xdperf.pdf](https://github.com/takehaya/xdperf/tree/main/docs/xdperf.pdf).

## Install

Note: You need to install `jq` beforehand.
```shell
# latest install
curl -fsSL https://raw.githubusercontent.com/takehaya/xdperf/main/scripts/install_xdperf.sh | sudo bash

# extra: select version mode
curl -fsSL https://raw.githubusercontent.com/takehaya/xdperf/main/scripts/install_xdperf.sh | sudo bash -s -- --version v0.5.3
```

## Usage
### Commands

xdperf has two main commands
| Command | Description |
|---------|-------------|
| `run` | Run the traffic generator (send or receive mode) |
| `probe` | Probe XDP capabilities of a network device |

### Basic Syntax

```shell
# Traffic generation
sudo xdperf run --device <interface> [options]

# Probe XDP support
sudo xdperf probe --device <interface> [--json]
```

By default, `simpleudp.tinygo` plugin is used (installed at `/usr/local/share/xdperf/plugins`).
For custom plugin development, see [Plugin Development Guide](./plugins/README.md).

### Basic Examples

```shell
# Send 10,000 packets with default settings
sudo xdperf run --device eth0 --count 10k

# Send packets for 30 seconds at 100k pps
sudo xdperf run --device eth0 --duration 30s --pps 100k
```

### High-Performance Traffic Generation

```shell
# High-throughput: 1M packets with 8 parallel threads at max speed
sudo xdperf run --device eth0 --count 1m --parallelism 8

# Rate-limited: 10 seconds at 500k pps with 4 threads
sudo xdperf run --device eth0 --duration 10s --pps 500k --parallelism 4
```

### Custom Packet Configuration

```shell
# Small packets for PPS testing
sudo xdperf run --device eth0 --count 1m --parallelism 4 \
    --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 64}'

# Large packets for throughput testing
sudo xdperf run --device eth0 --count 100k \
    --cfg '{"payload_size": 1400}'
```

### Server Mode (Receive Only)

```shell
# Receive only (server mode)
sudo xdperf run --device eth0 --send=false --recv

# Echo server with swap
sudo xdperf run --device eth0 --send=false --recv --swap-resp
```

### Development and Debugging

```shell
# Local build with verbose debugging
sudo ./out/bin/xdperf run \
    --plugin simpleudp.go \
    --plugin-path ./out/bin \
    --device eth0 \
    --count 100 \
    --debugmode 1

# With NIC statistics
sudo xdperf run --device eth0 --count 1m --show-nic-stats
```

### Probe Command

Check if your device supports XDP and live frame mode:

```shell
# Check XDP capabilities
sudo xdperf probe --device eth0

# Output in JSON format
sudo xdperf probe --device eth0 --json
```

Example output:
```
INFO    Probing XDP capabilities        {"device": "eth0"}
INFO    Device  {"name": "eth0"}
INFO    XDP Support     {"supported": true, "driver_mode": true, "generic_mode": true, "offload_mode": false}
INFO    BPF_PROG_RUN Support    {"live_frame_mode": true}
INFO    Summary: This device is fully compatible with xdperf
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
