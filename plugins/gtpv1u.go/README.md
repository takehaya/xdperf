# gtpv1u — GTPv1-U (5G/4G) traffic plugin

Generates GTPv1-U **G-PDU** (user-plane, message type `0xFF`) traffic:

```
Eth | IPv4 | UDP(dst 2152) | GTP-U [+ PSC ext hdr] | inner IPv4 | inner UDP/ICMP | payload
```

- **5G mode** (`enable_psc: true`, default): adds a PDU Session Container
  extension header (type `0x85`) carrying the **QFI**, with correct DL/UL
  octets per 3GPP TS 38.415.
- **4G / classic mode** (`enable_psc: false`): plain 8-byte GTP-U header.
- **TEID** and **QFI** sweep sequentially (`*_start`/`*_end`); when `start == end`
  the field is fixed.
- **Packet size** varies IMIX-style across several fixed-size variants
  (`imix_sizes` / `imix_weights`) — no runtime length mutation.

## Build

The Makefile auto-detects the directory; from the repo root:

```sh
make build-plugins        # builds out/bin/gtpv1u.go.wasm (and the others)
# or just this one:
make gtpv1u.go
```

## Run

```sh
sudo out/bin/xdperf run --device eth0 --count 1m \
    --plugin gtpv1u.go --plugin-language go \
    --cfg '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2",
            "teid_start":1,"teid_end":1000,"enable_psc":true,
            "qfi_start":1,"qfi_end":9,
            "inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2"}'
```

Pass config inline with `--cfg` (alias `--plugin-config`) or from a file with
`--cfgpath`.

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `src_ip` / `dst_ip` | string | `10.0.0.1` / `10.0.0.2` | Outer IPv4 addresses |
| `dst_mac` | string | `ff:ff:ff:ff:ff:ff` | Outer dst MAC (ignored when `is_arp_resolve`) |
| `is_arp_resolve` | bool | `true` | Resolve `dst_mac` from `dst_ip` via ARP/NDP |
| `src_port` | uint16 | `2152` | Outer UDP source port (destination is fixed to 2152) |
| `teid_start` / `teid_end` | uint32 | `1` / `1` | TEID range (`end > start` to sweep) |
| `enable_psc` | bool | `true` | Add the 5G PDU Session Container extension header |
| `enable_seq` | bool | `false` | Set the GTP-U sequence-number flag |
| `pdu_type` | string | `dl` | PSC PDU type: `dl` or `ul` (different octets per TS 38.415) |
| `rqi` | bool | `false` | PSC Reflective QoS Indicator (downlink-only; ignored for `ul`) |
| `qfi_start` / `qfi_end` | uint8 | `9` / `9` | QFI range 0-63 (`end > start` to sweep) |
| `inner_proto` | string | `udp` | Inner T-PDU: `udp` or `icmp` (ICMPv4 echo request) |
| `inner_udp_checksum` | bool | `false` | Compute the inner UDP checksum (`udp` only); default leaves it 0 (legal over IPv4) |
| `inner_src_ip` / `inner_dst_ip` | string | `192.168.0.1` / `192.168.0.2` | Inner IPv4 addresses |
| `inner_src_port` / `inner_dst_port` | uint16 | `1024` / `5060` | Inner UDP ports (`udp` only) |
| `vary_inner_port` | bool | `false` | Sweep the inner UDP source port (`udp` only) |
| `imix_sizes` | []int | `[128,768,1400]` | Total frame sizes; one base-packet variant each |
| `imix_weights` | []int | `[7,2,1]` | Weights matched positionally to `imix_sizes` |

### Examples

```jsonc
// Uplink PSC, QFI 1..9
{"pdu_type":"ul","enable_psc":true,"qfi_start":1,"qfi_end":9}

// Classic 4G (no PSC), TEID sweep
{"enable_psc":false,"teid_start":1,"teid_end":1000}

// Inner ICMP echo
{"inner_proto":"icmp"}
```

## Capturing the generated traffic

`xdperf run` transmits via XDP (`BPF_PROG_TEST_RUN` live frames) and does not
write a pcap. Capture with [xdp-ninja](https://github.com/takehaya/xdp-ninja),
which observes at XDP-time and can walk the inner GTP-U headers:

```sh
# while xdperf is sending, find the xdp_tx program id and attach:
sudo xdp-ninja -p "$(sudo bpftool prog show | awk '/name xdp_tx /{print $1+0; exit}')" \
    --mode exit -w gtpv1u.pcap
tshark -r gtpv1u.pcap.cpu0 \
    -T fields -e frame.len -e gtp.teid -e gtp.ext_hdr.pdu_ses_con.qos_flow_id
```

> Capture is per-CPU sharded (`gtpv1u.pcap.cpuN`); merge with
> `mergecap` if you send on multiple cores. xdp-ninja v0.12+ is recommended —
> earlier builds could alias buffers and corrupt records under mixed frame sizes.

## Layout & tests

```
gtpv1u.go/
  main.go            plugin_init / plugin_process / plugin_cleanup (wasm exports)
  config.go          GeneratorRequest (JSON config)
  builder/           packet construction (gopacket) — host-testable
  builder/*_test.go  go test ./builder/   (offsets, checksums, PSC DL/UL, inner ICMP/UDP)
```

```sh
cd plugins/gtpv1u.go && go test ./builder/
```

A host-side integration test that loads the built wasm lives at
`pkg/plugin/gtpv1u_integration_test.go` (run from the repo root, skips if the
plugin is not built).
