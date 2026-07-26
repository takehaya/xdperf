# srv6 — SRv6 (RFC 8754) traffic plugin

Generates SRv6-encapsulated traffic:

```
Eth | IPv6 (NH=43) | SRH | inner packet | payload
```

The `mode` field selects what the SRH carries:

| Mode | SRH next header | Inner packet | Min frame (1 segment) |
|------|-----------------|--------------|-----------------------|
| `l3vpn_ipv4` (default) | 4 (IPv4-in-IPv6) | IPv4 + UDP | 106 B |
| `l2vpn_eth` | 143 (Ethernet) | Ethernet + IPv4 + UDP | 120 B |
| `ipv6` | 41 (IPv6-in-IPv6) | IPv6 + UDP | 126 B |

Each extra segment adds 16 bytes to the minimum.

- **Segment list**: `segments` in visiting order (`segments[0]` is the first
  segment to visit, the last element is the final segment). Stored reversed in
  the SRH per RFC 8754 (Segment List[0] holds the final segment), with
  `Segments Left` = `Last Entry` = n-1. Up to 127 segments (the 8-bit Hdr Ext
  Len limit).
- **Outer destination**: when `dst_ip` is empty (the default) the outer IPv6
  destination is `segments[0]`, the first segment to visit — the slot
  `Segments Left` points at.
- **Sweeps** (each toggled independently): 20-bit IPv6 flow label
  (`flow_label_start`/`flow_label_end`), 16-bit SRH tag
  (`srh_tag_start`/`srh_tag_end`), inner UDP source/destination port
  (`vary_inner_src_port` / `vary_inner_dst_port`), inner source IP
  (`vary_inner_ip`: full address in the IPv4 modes, last hextet in `ipv6` mode).
- **Packet size** varies IMIX-style across several fixed-size variants
  (`imix_sizes` / `imix_weights`) — no runtime length mutation.

> The outer IPv6 header has no checksum. The data plane recomputes the inner
> IPv4 header + inner UDP checksums (`l3vpn_ipv4` / `l2vpn_eth`) or the inner
> UDP checksum over the IPv6 pseudo header (`ipv6` mode). The inner UDP
> checksum is always computed — a zero UDP checksum is illegal over IPv6
> (RFC 8200).

## Build

The Makefile auto-detects the directory; from the repo root:

```sh
make build-plugins        # builds out/bin/srv6.go.wasm (and the others)
# or just this one:
make srv6.go
```

## Run

```sh
sudo out/bin/xdperf run --device eth0 --count 1m \
    --plugin srv6.go --plugin-language go \
    --cfg '{"src_ip":"2001:db8::1",
            "segments":["2001:db8:100::1","2001:db8:200::1"],
            "vary_inner_src_port":true}'
```

Pass config inline with `--cfg` (alias `--plugin-config`) or from a file with
`--cfgpath`.

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `l3vpn_ipv4` | `l3vpn_ipv4` \| `l2vpn_eth` \| `ipv6` |
| `segments` | []string | `["2001:db8:100::1"]` | SID list in visiting order, 1-127 IPv6 addresses |
| `src_ip` | string | `2001:db8::1` | Outer IPv6 source |
| `dst_ip` | string | (empty) | Outer IPv6 destination; empty = `segments[0]` (first-visited) |
| `dst_mac` | string | `ff:ff:ff:ff:ff:ff` | Outer dst MAC (ignored when `is_arp_resolve`) |
| `is_arp_resolve` | bool | `true` | Resolve the outer dst MAC via NDP for the outer dst IP |
| `traffic_class` | uint8 | `0` | Outer IPv6 traffic class |
| `flow_label_start` / `flow_label_end` | uint32 | `0` / `0` | 20-bit flow label range 0-1048575 (`end > start` to sweep) |
| `srh_tag_start` / `srh_tag_end` | uint16 | `0` / `0` | 16-bit SRH tag range (`end > start` to sweep) |
| `inner_src_mac` / `inner_dst_mac` | string | `02:00:00:00:01:01` / `02:00:00:00:01:02` | Inner Ethernet MACs (`l2vpn_eth` only) |
| `inner_src_ip` / `inner_dst_ip` | string | `192.168.0.1` / `192.168.0.2` | Inner IPv4 addresses (`l3vpn_ipv4` / `l2vpn_eth`) |
| `inner_src_ip6` / `inner_dst_ip6` | string | `fd00::1` / `fd00::2` | Inner IPv6 addresses (`ipv6` mode) |
| `inner_src_port` / `inner_dst_port` | uint16 | `1024` / `5060` | Inner UDP ports |
| `vary_inner_src_port` | bool | `false` | Sweep the inner UDP source port |
| `vary_inner_dst_port` | bool | `false` | Sweep the inner UDP destination port |
| `vary_inner_ip` | bool | `false` | Sweep the inner source IP (full IPv4 / last IPv6 hextet) |
| `imix_sizes` | []int | `[256,768,1400]` | Total frame sizes; one base-packet variant each |
| `imix_weights` | []int | `[7,2,1]` | Weights matched positionally to `imix_sizes` |

Per-variant diff budget: all five sweeps enabled at once use 5 of the 8
available diff slots and at most 2 of the 4 checksum slots.

### Examples

```jsonc
// L3VPN over a 2-segment policy, flow-label sweep for ECMP entropy
{"mode":"l3vpn_ipv4","segments":["2001:db8:100::1","2001:db8:200::1"],
 "flow_label_start":0,"flow_label_end":1048575}

// L2VPN (End.DX2-style): inner Ethernet frame behind the SRH
{"mode":"l2vpn_eth","segments":["2001:db8:100::1"],
 "inner_src_mac":"a2:00:00:00:00:01","inner_dst_mac":"a2:00:00:00:00:02"}

// IPv6-in-IPv6 (End.DX6-style), sweep the inner source port
{"mode":"ipv6","segments":["2001:db8:100::1"],"vary_inner_src_port":true}

// SRH tag sweep with a fixed flow label
{"segments":["2001:db8:100::1"],"srh_tag_start":0,"srh_tag_end":4095}
```

## Capturing the generated traffic

`xdperf run` transmits via XDP (`BPF_PROG_TEST_RUN` live frames) and does not
write a pcap. Capture with [xdp-ninja](https://github.com/takehaya/xdp-ninja),
which observes at XDP-time and can walk the SRH into the inner headers:

```sh
# while xdperf is sending, find the xdp_tx program id and attach:
sudo xdp-ninja -p "$(sudo bpftool prog show | awk '/name xdp_tx /{print $1+0; exit}')" \
    --mode exit -w srv6.pcap
tshark -r srv6.pcap.cpu0 -Y ipv6.routing \
    -T fields -e frame.len -e ipv6.routing.type -e ipv6.flow -e udp.srcport
```

> Capture is per-CPU sharded (`srv6.pcap.cpuN`); merge with `mergecap` if you
> send on multiple cores.

## Performance note

Encapsulated checksums (the inner specs behind the SRH) bypass the data
plane's incremental checksum cache and are fully recomputed per packet — the
same behavior as MPLS/GTP-U inner checksums. Expect somewhat lower peak pps
than a flat UDP workload at the same size.

## Layout & tests

```
srv6.go/
  main.go            plugin_init / plugin_process / plugin_cleanup (wasm exports)
  config.go          GeneratorRequest (JSON config)
  builder/           packet construction (gopacket) — host-testable
  builder/*_test.go  go test ./builder/   (SRH layout, segment reversal, offsets, checksums)
```

```sh
cd plugins/srv6.go && go test ./builder/
```

A host-side integration test that loads the built wasm lives at
`pkg/plugin/srv6_integration_test.go` (run from the repo root, skips if the
plugin is not built).
