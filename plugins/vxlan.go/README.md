# vxlan — VXLAN (RFC 7348) traffic plugin

Generates VXLAN-encapsulated traffic:

```
Eth | IPv4 | UDP(dst 4789) | VXLAN(8) | inner Eth | inner IPv4 | inner UDP | payload
```

- **24-bit VNI** sweeps sequentially (`vni_start`/`vni_end`); when `start == end`
  the VNI is fixed.
- **Inner Ethernet frame**: a full inner L2 header (configurable inner src/dst
  MAC). `inner_mode: ip` (default) adds inner IPv4/UDP (92-byte minimum);
  `inner_mode: l2only` carries just the inner Ethernet header + padding
  (**64-byte minimum**), for minimum-size / peak-pps testing.
- **Sweeps** (each toggled independently): inner UDP source port
  (`vary_inner_port`), inner source IP (`vary_inner_ip`), outer UDP source port
  (`vary_outer_port`). In `l2only` mode the inner IP/port sweeps are ignored
  (there is no inner L3/L4).
- **Packet size** varies IMIX-style across several fixed-size variants
  (`imix_sizes` / `imix_weights`) — no runtime length mutation.

> The outer UDP checksum is left **0**, the RFC 7348 default. Unlike GTP-U, no
> outer UDP checksum spec is emitted, so the data plane never writes it. The
> outer IPv4 and inner IPv4 (and optionally inner UDP) checksums are recomputed.

## Build

The Makefile auto-detects the directory; from the repo root:

```sh
make build-plugins        # builds out/bin/vxlan.go.wasm (and the others)
# or just this one:
make vxlan.go
```

## Run

```sh
sudo out/bin/xdperf run --device eth0 --count 1m \
    --plugin vxlan.go --plugin-language go \
    --cfg '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2",
            "vni_start":100,"vni_end":200,
            "inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2",
            "vary_inner_port":true}'
```

Pass config inline with `--cfg` (alias `--plugin-config`) or from a file with
`--cfgpath`.

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `src_ip` / `dst_ip` | string | `10.0.0.1` / `10.0.0.2` | Outer IPv4 addresses |
| `dst_mac` | string | `ff:ff:ff:ff:ff:ff` | Outer dst MAC (ignored when `is_arp_resolve`) |
| `is_arp_resolve` | bool | `true` | Resolve `dst_mac` from `dst_ip` via ARP/NDP |
| `src_port` | uint16 | `0` | Outer UDP source port (sweep start when `vary_outer_port`) |
| `dst_port` | uint16 | `4789` | Outer UDP destination port (IANA VXLAN port) |
| `vni_start` / `vni_end` | uint32 | `100` / `100` | 24-bit VNI range 0-16777215 (`end > start` to sweep) |
| `inner_mode` | string | `ip` | `ip` = inner Ethernet+IPv4+UDP (92B min); `l2only` = inner Ethernet only (64B min) |
| `inner_src_mac` / `inner_dst_mac` | string | `02:00:00:00:01:01` / `02:00:00:00:01:02` | Inner Ethernet MACs |
| `inner_udp_checksum` | bool | `false` | Compute the inner UDP checksum; default leaves it 0 (legal over IPv4) |
| `inner_src_ip` / `inner_dst_ip` | string | `192.168.0.1` / `192.168.0.2` | Inner IPv4 addresses |
| `inner_src_port` / `inner_dst_port` | uint16 | `1024` / `5060` | Inner UDP ports |
| `vary_inner_port` | bool | `false` | Sweep the inner UDP source port |
| `vary_inner_ip` | bool | `false` | Sweep the inner source IP |
| `vary_outer_port` | bool | `false` | Sweep the outer UDP source port |
| `imix_sizes` | []int | `[128,768,1400]` | Total frame sizes; one base-packet variant each |
| `imix_weights` | []int | `[7,2,1]` | Weights matched positionally to `imix_sizes` |

### Examples

```jsonc
// VNI sweep 100..200
{"vni_start":100,"vni_end":200}

// Single VNI, sweep inner source port for RSS/ECMP spread
{"vni_start":4242,"vni_end":4242,"vary_inner_port":true,"inner_udp_checksum":true}

// Sweep outer source port (encapsulator entropy)
{"vary_outer_port":true,"src_port":1024}

// Minimum-size 64B frames for peak-pps testing (inner L2 only)
{"inner_mode":"l2only","vni_start":100,"vni_end":200,"imix_sizes":[64],"imix_weights":[1]}
```

## Throughput / round-trip benchmarking

For peak packets-per-second, **pass `--batch-size` (default `1`)** — it sets how
many frames each `BPF_PROG_TEST_RUN` live-frame call submits. A batch size of 1
caps a single 100G port at ~23 Mpps regardless of cores/diffs/checksums; a batch
of 64 reaches line-rate territory.

Round-trip (Both mode here, a swap-echo on the peer), 64-byte `l2only` frames,
24 NIC-local cores, on a back-to-back 100G E810 link:

```sh
# peer (echo): no plugin needed in pure-recv mode
sudo xdperf run --device <nic> --send=false --recv --swap-resp --batch-size 64

# sender (Both mode), sweep the outer UDP source port so RSS spreads the return
# traffic across the echo's RX queues:
sudo out/bin/xdperf run --device <nic> --send --recv \
    --infinite --count 200k --parallelism 24 --cpu-mode local --batch-size 64 \
    --plugin vxlan.go -L go --plugin-path out/bin \
    --cfg '{"src_ip":"192.168.1.1","dst_ip":"192.168.1.2","is_arp_resolve":true,
            "inner_mode":"l2only","vni_start":100,"vni_end":200,
            "vary_outer_port":true,"imix_sizes":[64],"imix_weights":[1]}'
# observed: ~102-105 Mpps xmit, ~101-103 Mpps recv (round-trip near-symmetric)
```

Notes:
- `vary_outer_port` is what makes RSS distribute traffic across multiple RX
  queues/cores; without it the return path funnels into one queue and `recv`
  caps well below `xmit`.
- The outer UDP destination stays `4789` and the echo only swaps the outer
  MAC/IP, so the inner frame and VNI are reflected unchanged.

## Capturing the generated traffic

`xdperf run` transmits via XDP (`BPF_PROG_TEST_RUN` live frames) and does not
write a pcap. Capture with [xdp-ninja](https://github.com/takehaya/xdp-ninja),
which observes at XDP-time and can walk the inner VXLAN headers:

```sh
# while xdperf is sending, find the xdp_tx program id and attach:
sudo xdp-ninja -p "$(sudo bpftool prog show | awk '/name xdp_tx /{print $1+0; exit}')" \
    --mode exit -w vxlan.pcap
tshark -r vxlan.pcap.cpu0 -Y vxlan \
    -T fields -e frame.len -e vxlan.vni -e ip.src -e udp.srcport
```

> Capture is per-CPU sharded (`vxlan.pcap.cpuN`); merge with `mergecap` if you
> send on multiple cores.

## Layout & tests

```
vxlan.go/
  main.go            plugin_init / plugin_process / plugin_cleanup (wasm exports)
  config.go          GeneratorRequest (JSON config)
  builder/           packet construction (gopacket) — host-testable
  builder/*_test.go  go test ./builder/   (offsets, VNI, checksums, outer UDP=0, l2only 64B)
```

```sh
cd plugins/vxlan.go && go test ./builder/
```

A host-side integration test that loads the built wasm lives at
`pkg/plugin/vxlan_integration_test.go` (run from the repo root, skips if the
plugin is not built).
