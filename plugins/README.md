# xdperf WASM Plugin Quick Guide

This guide explains how to develop plugins based on `simpleudp.tinygo`.

## Overview
The host (xdperf) loads WASM modules and calls the following function handlers to obtain packet data.
By implementing a plugin, users can create custom packet generators.

## Required Exports
```go
//go:wasmexport plugin_init
func plugin_init(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 { ... }

//go:wasmexport plugin_process
func plugin_process(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 { ... }

//go:wasmexport plugin_cleanup
func plugin_cleanup(inputPtr, inputLen, outputPtr, outputMaxLen uint32) int32 { ... }
```

The `plugin_process` function is where packet generation happens.
TinyGo and C plugins use input/output buffers in WASM memory and export
`malloc`/`free` as well. Standard Go plugins use
[`pkg/guest/goshim`](../pkg/guest/goshim/) host imports to exchange the same
JSON requests and responses; the four export arguments are unused in that adapter.
A response is limited to 32 MiB in either ABI.

## Directory Structure Example
```
plugins/simpleudp.tinygo/
  main.go      // Exports + logic
  config.go    // Request/Response definitions
  packet.go    // Packet generation
  go.mod       // Standalone module
```

## Key Types
See [pkg/guest/surface.go](https://github.com/takehaya/xdperf/tree/main/pkg/guest/surface.go) for the types that plugins should return.

`PacketVariant.kind` is omitted or `packet` for the packet engine, or `tcp_flow`
for stateful TCP. A set containing TCP must use `pattern: "mixed"`; packet
variants are optional. Weights allocate TX iterations, not bytes or
completed connections. TCP variants accept an optional `base_packet`,
`tcp_flow.encapsulation`, `timestamps`, `payload_pattern`, and restricted
per-flow `variable_params`; see the [mixed guide](../docs/ja/mixed_variants.md).
The removed standalone TCP scenario API is not accepted.

Go VXLAN layout definitions and codecs are generated from the
[C shared header](vxlan.c/vxlan_shared.h) into
[`guest/packetdefs/vxlan`](../pkg/guest/packetdefs/vxlan/).
Use `make packetdefs-gen` to regenerate and `make packetdefs-check` to detect
drift with LLVM 22. Normal plugin builds use the committed generated files.

## Host Imports
Several utility functions are exported from the host and can be used as an SDK.
Functions defined in `pkg/guest/api.go` can be called from plugins.

## Build (TinyGo)
```bash
cd plugins/simpleudp.tinygo
tinygo build -scheduler=none -target=wasip1 -buildmode=c-shared -o ../../out/bin/simpleudp.tinygo.wasm .
```
Key flags: `-target=wasip1` / `-buildmode=c-shared` / `-scheduler=none`.

## Build (Go)
```bash
cd plugins/simpleudp.go
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o ../../out/bin/simpleudp.go.wasm .
```
Key flags: `GOOS=wasip1` / `GOARCH=wasm` / `-buildmode=c-shared`.

## Using Makefile

From the project root:
```bash
# Build Go, TinyGo, and available C plugins
make build-plugins

# Build a specific plugin
make simpleudp.tinygo  # TinyGo version
make simpleudp.go      # Go version
```

## Examples

For implementation details including memory helpers and packet generation, see the sample plugins:
- [simpleudp.tinygo](./simpleudp.tinygo/) - TinyGo-based plugin
- [simpleudp.go](./simpleudp.go/) - Go-based plugin
- [imixudp.go](./imixudp.go/) - Weighted IMIX traffic via multiple variants
- [gtpv1u.go](./gtpv1u.go/) - GTPv1-U (5G/4G) tunneled traffic with PSC/QFI support
- [vxlan.go](./vxlan.go/) - VXLAN (RFC 7348) tunneled traffic with VNI sweep and an inner Ethernet frame
- [tcpflow.go](./tcpflow.go/README.md) - Minimal TCP-only flows with host route resolution
- [tcpudp.go](./tcpudp.go/README.md) - Minimal weighted UDP packet and TCP flow example
- [mixed.go](./mixed.go/README.md) - Weighted packet and TCP flow variants, with optional TCP templates and tunnels
- [vxlan.c](./vxlan.c/README.md) - Freestanding C VXLAN generator; needs clang and wasm-ld
- [srv6.go](./srv6.go/) - SRv6 (RFC 8754) tunneled traffic with L3VPN/L2VPN/IPv6 modes, segment list, flow-label and SRH-tag sweeps

## simpleudp Plugin Configuration

The `simpleudp` plugin accepts the following configuration parameters via `--plugin-config` or `--plugin-config-path`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `src_ip` | string | `192.168.1.1` | Source IP address |
| `dst_ip` | string | `192.168.1.2` | Destination IP address |
| `src_port` | uint16 | `1234` | Source port |
| `dst_port` | uint16 | `5678` | Destination port |
| `payload_size` | int | `1024` | UDP payload size in bytes |
| `vlan_id` | uint16 | `0` | Outer 802.1Q VLAN ID 1-4094; `0` = no VLAN tag |
| `vlan_pcp` | uint8 | `0` | Outer VLAN priority (PCP), only used when `vlan_id` > 0 |

**Example:**
```shell
sudo xdperf run --device eth0 --count 1m \
    --cfg '{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 9999, "payload_size": 512}'
```
