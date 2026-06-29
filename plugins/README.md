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
The host writes config/input/output buffers to WASM memory. The plugin reads input, generates JSON response, and writes it back.

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
# Build all plugins (both TinyGo and Go versions)
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

## simpleudp Plugin Configuration

The `simpleudp` plugin accepts the following configuration parameters via `--plugin-config` or `--plugin-config-path`:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `src_ip` | string | `192.168.1.1` | Source IP address |
| `dst_ip` | string | `192.168.1.2` | Destination IP address |
| `src_port` | uint16 | `1234` | Source port |
| `dst_port` | uint16 | `5678` | Destination port |
| `payload_size` | int | `1024` | UDP payload size in bytes |

**Example:**
```shell
sudo xdperf --device eth0 --count 1m \
    --cfg '{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 9999, "payload_size": 512}'
```

## gtpv1u Plugin Configuration

The `gtpv1u` plugin generates GTPv1-U (G-PDU, message type `0xFF`) data-plane
traffic: outer `Ethernet / IPv4 / UDP(dst 2152) / GTP-U` encapsulating an inner
`IPv4 / UDP` packet. When `enable_psc` is set it adds a 5G PDU Session Container
extension header (type `0x85`) so the QFI can be exercised. TEID and QFI use a
`_start`/`_end` pair: equal values keep the field fixed, `end > start` increments
it sequentially per packet. Packet-length diversity is produced IMIX-style from
the fixed-size variants in `imix_sizes` (no runtime length mutation). The outer
IPv4, inner IPv4 and outer UDP checksums are recomputed; the inner UDP checksum
is left 0 (disabled) by default and only recomputed when `inner_udp_checksum` is
set.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `src_ip` | string | `10.0.0.1` | Outer source IP address |
| `dst_ip` | string | `10.0.0.2` | Outer destination IP address |
| `dst_mac` | string | `ff:ff:ff:ff:ff:ff` | Outer destination MAC (ignored when `is_arp_resolve`) |
| `is_arp_resolve` | bool | `true` | Resolve `dst_mac` from `dst_ip` via ARP/NDP |
| `src_port` | uint16 | `2152` | Outer UDP source port (destination is fixed to 2152) |
| `teid_start` | uint32 | `1` | First GTP-U TEID |
| `teid_end` | uint32 | `1` | Last GTP-U TEID (`> start` to sweep) |
| `enable_psc` | bool | `true` | Add the 5G PDU Session Container extension header |
| `enable_seq` | bool | `false` | Set the GTP-U sequence-number flag |
| `pdu_type` | string | `dl` | PSC PDU type: `dl` (downlink) or `ul` (uplink). DL and UL carry different octets per 3GPP TS 38.415 |
| `rqi` | bool | `false` | PSC Reflective QoS Indicator bit. Downlink-only — ignored for `pdu_type: ul` |
| `qfi_start` | uint8 | `9` | First QFI (0-63) |
| `qfi_end` | uint8 | `9` | Last QFI (`> start` to sweep) |
| `inner_proto` | string | `udp` | Inner T-PDU transport: `udp` or `icmp` (ICMPv4 echo request) |
| `inner_udp_checksum` | bool | `false` | Compute/maintain the inner UDP checksum (`udp` only). Default leaves it 0 (disabled — legal over IPv4) |
| `inner_src_ip` | string | `192.168.0.1` | Inner (T-PDU) source IP |
| `inner_dst_ip` | string | `192.168.0.2` | Inner (T-PDU) destination IP |
| `inner_src_port` | uint16 | `1024` | Inner UDP source port (`inner_proto: udp` only) |
| `inner_dst_port` | uint16 | `5060` | Inner UDP destination port (`inner_proto: udp` only) |
| `vary_inner_port` | bool | `false` | Sweep the inner UDP source port (`inner_proto: udp` only) |
| `imix_sizes` | []int | `[128,768,1400]` | Total frame sizes (one variant each) |
| `imix_weights` | []int | `[7,2,1]` | Weights matched positionally to `imix_sizes` |

> Inner checksums: the default inner UDP carries no checksum (0), which is robust
> across IMIX sizes. `inner_proto: icmp` (or `inner_udp_checksum: true`) keeps a
> real inner checksum, but mixing several `imix_sizes` can leave it inconsistent
> on the wire; use a single `imix_sizes` entry when an exact inner checksum
> matters.

**Example:**
```shell
sudo xdperf run --device eth0 --count 1m \
    --plugin gtpv1u.go --plugin-language go \
    --cfg '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","teid_start":1,"teid_end":1000,
            "enable_psc":true,"qfi_start":1,"qfi_end":9,
            "inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2"}'
```

### Capturing generated packets

`xdperf run` transmits via XDP and does not write a pcap. Capture the GTP-U
traffic with [xdp-ninja](https://github.com/takehaya/xdp-ninja), which captures
at XDP-time and can walk into the inner headers (TEID/QFI/inner IP) that
tcpdump's cBPF cannot reach:

```shell
# While `xdperf run --plugin gtpv1u.go ...` is sending on eth0:
sudo xdp-ninja -i eth0 "eth/ipv4/udp/gtp/ipv4/udp" -w gtpv1u.pcap
tshark -r gtpv1u.pcap \
    -T fields -e frame.number -e gtp.teid \
    -e gtp.ext_hdr.pdu_ses_con.qos_flow_id -e ip.checksum.status
```
