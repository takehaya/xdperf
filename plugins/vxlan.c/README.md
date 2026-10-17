# vxlan.c — an xdperf plugin written in C

VXLAN (RFC 7348) traffic whose outer headers stay fixed while the inner UDP
source port sweeps `inner_flows` values. To GRO, RSS and any per-flow logic
that keys on the outer 5-tuple it is one flow; a datapath component that looks
inside the tunnel sees `inner_flows` flows.

The plugin is plain C built freestanding for wasm32 (no libc, no WASI). It
uses the same ABI as the TinyGo plugins (`plugin_init/process/cleanup` taking
`(in_ptr, in_len, out_ptr, out_cap)` and returning the JSON length, plus
`malloc`/`free`), so `-L c` (any language other than `go`) loads it.

`vxlan_shared.h` holds the packet layout with compiler builtin types only, so a
BPF program can include the very same file to parse what this plugin builds
(for example a Cilium Datapath Plugin that counts inner flows). Keep the header
free of `memcpy` on packet data: Cilium's BPF headers replace `memcpy` and
turn unaligned copies into a compile-time trap; use `vx_load16`/`vx_load32`.

## Build

Needs clang with the WebAssembly target and `wasm-ld` (lld):

```sh
make -C plugins/vxlan.c            # -> out/bin/vxlan.c.wasm
go test ./pkg/plugin -run TestVXLANCPluginIntegration
```

## Config

| key | default | meaning |
|---|---|---|
| `src_mac`, `dst_mac` | (required) | outer Ethernet |
| `src_ip`, `dst_ip` | (required) | outer IPv4 |
| `src_port` | 49152 | outer UDP source port (fixed) |
| `vni` | 100 | VXLAN network identifier |
| `inner_src_ip`, `inner_dst_ip` | (required) | inner IPv4 |
| `inner_dport` | 5000 | inner UDP destination port |
| `inner_sport_base` | 10000 | first inner UDP source port |
| `inner_flows` | 1 | number of inner source ports (inner flows) |
| `payload` | 18 | inner UDP payload bytes |

```sh
xdperf run --device eth0 -L c -p vxlan.c -P out/bin --infinite --count 16384 \
  --cfg '{"src_mac":"02:00:00:00:00:01","dst_mac":"02:00:00:00:00:02","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","inner_src_ip":"192.168.0.1","inner_dst_ip":"192.168.0.2","inner_flows":16384}'
```

Use `--count` of at least `inner_flows` so the packet pool covers every inner flow.
