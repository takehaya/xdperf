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


sudo xdperf run --device ens4 --count 100k --parallelism 10 \
    --cfg '{"dst_port": 10001, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "payload_size": 64}'
```

### TCP Stream Mode

`--tcp` opens real TCP connections entirely from XDP (SYN, data, retransmissions, FIN) against any
TCP server, iperf3-style, without using a kernel socket on the sender. See
[docs/ja/tcp_stream.md](docs/ja/tcp_stream.md) and the design notes in
[docs/ja/design_xdp_tcp.md](docs/ja/design_xdp_tcp.md).

```bash
# receiver: any TCP sink; xdperf-sink counts connections and bytes
xdperf-sink -listen 10.0.0.2:5201

# sender: 64 connections x 1 GB over 4 CPUs
sudo xdperf run --tcp --device eth0 --tcp-dst 10.0.0.2:5201 --tcp-flows 64 --tcp-bytes 1g --parallelism 4

# IPv6 / VLAN-tagged / time-bounded
sudo xdperf run --tcp --device eth0 --tcp-dst '[fd00::2]:5201' --tcp-flows 16 --duration 30s
sudo xdperf run --tcp --device eth0 --tcp-dst 10.0.100.2:5201 --tcp-vlan-id 100 --tcp-flows 8 --tcp-bytes 100m

# XDP responder: answer SYN / data / FIN from XDP too (no kernel socket on either side).
# Works with the --tcp client above or with any one-way Linux TCP sender (socat, nc).
# It never sends data back, so request/response clients (iperf3 -c, curl) do not work.
sudo xdperf run --tcp-server --device eth0 --tcp-listen 10.0.0.2:5201
```

### Mixed Packet and TCP Variants

Use `--plugin mixed.go` without `--tcp` to combine packet templates and TCP flows.
Weights allocate TX iterations; TCP waits can make the actual frame ratio differ.
`--count` limits TX worker frames across packet and TCP variants, including retransmissions.
The run can finish below this limit when all TCP flows complete first.
At the limit, open flows produce a warning and exit successfully unless a flow failed.
Finite TCP-only sets can omit both `--count` and `--duration`.

```bash
sudo xdperf run --device eth0 --plugin mixed.go --count 100000 --pps 2000 \
    --cfg '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02"}' \
    --tcp-flow-report flows.csv
```

The peer must provide a TCP sink at port 5201.
See the [sample plugin](plugins/mixed.go/README.md) and
[Japanese mixed-traffic guide](docs/ja/mixed_variants.md) for TCP templates,
tunnels, timestamps, payload patterns, per-flow parameters, RX diagnostics,
and startup behavior. `--tcp-flow-report` also works with standalone `--tcp`.
For veth tests with several workers, set `VETH_QUEUES` when creating the pair;
see [examples](examples/README.md#veth-queues).

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

### Metrics Export (OTLP)

Export TX/RX statistics to an OpenTelemetry Collector over OTLP/gRPC, in both
send and receive mode. See [docs/cli.md](./docs/cli.md#--otlp-endpoint----otlp-interval----otlp-insecure----otlp-attributes) for the metric list and collector setup, or the Japanese guide at [docs/ja/otlp_metrics.md](./docs/ja/otlp_metrics.md) for a full walkthrough including a Prometheus + Grafana pipeline.

```shell
# Push metrics every 10s to a local collector
sudo xdperf run --device eth0 --count 1m \
    --otlp-endpoint localhost:4317 --otlp-insecure

# Tag a benchmark run with custom resource attributes
sudo xdperf run --device eth0 --duration 60s --pps 1m \
    --otlp-endpoint collector.example.com:4317 \
    --otlp-attributes test.run.id=run42,site=lab1
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

# Build Go, TinyGo, and available C plugins
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

### Shared C Packet Definitions

The Go VXLAN plugin uses definitions generated from
[`vxlan_shared.h`](plugins/vxlan.c/vxlan_shared.h). Normal builds use committed
Go files and need no generator toolchain. To update or verify them with LLVM 22:

```shell
make packetdefs-gen
make packetdefs-check
make packetdefs-test
```

See the [generation design](docs/ja/design_c_to_go_shared_defs.md) for the
manifest, fixed Docker environment, and ABI checks.

### Multi kernel version test
```shell
# Prerequisite: install vimto with static linking (once)
CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0

# Enable KVM access (once, resets on reboot)
sudo chmod 0666 /dev/kvm

# Run tests on a specific kernel version
vimto -kernel :6.1 -- go test -v -count 1 -timeout 5m ./pkg/coreelf/ -run TestBpf
vimto -kernel :6.6 -- go test -v -count 1 -timeout 5m ./pkg/coreelf/ -run TestBpf
vimto -kernel :6.12 -- go test -v -count 1 -timeout 5m ./pkg/coreelf/ -run TestBpf
vimto -kernel :6.18 -- go test -v -count 1 -timeout 5m ./pkg/coreelf/ -run TestBpf
vimto -kernel :7.0 -- go test -v -count 1 -timeout 5m ./pkg/coreelf/ -run TestBpf
vimto -kernel :7.1 -- go test -v -count 1 -timeout 5m ./pkg/coreelf/ -run TestBpf
```

## Inspired by
- We implemented the packet transmission mechanism with reference to [xdp-trafficgen](https://github.com/xdp-project/xdp-tools/tree/main/xdp-trafficgen). I think elements such as its probe implementation are excellent.
- We adopted the name xdperf simply because we thought it was a good name. See also [https://github.com/higebu/xdperf](https://github.com/higebu/xdperf)
