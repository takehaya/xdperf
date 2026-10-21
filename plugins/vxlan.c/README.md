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

The Go plugin uses generated types and codecs from this header via
[`pkg/guest/packetdefs/vxlan`](../../pkg/guest/packetdefs/vxlan/).
Run `make packetdefs-gen` or `make packetdefs-check` with LLVM 22 after shared
layout changes. This generates definitions, not the C inline function bodies;
see the [design](../../docs/ja/design_c_to_go_shared_defs.md).

The stage 6 observer for Cilium v1.20.3 assigns the numeric results of `vx_load16` / `vx_load32` and `vxlan_vni` to `vx_inner_key` fields and stores them in the byte order of the host running BPF (little endian on the tested x86_64 host).
The pinned header's `network byte order` comment does not describe this storage order; correcting it remains pending for the next header revision.
Exchanging Go `InnerKey` values with this map requires the BPF host's byte order, regardless of the Wasm guest's byte order.
No `InnerKey` codec is provided.
See [design section 11.2](../../docs/ja/design_c_to_go_shared_defs.md#112-段階6の-cilium-datapath-plugin-での確認) for the raw bytes and comparison results.

## Build

Needs clang with the WebAssembly target, `wasm-ld` (lld), and make.
On Debian or Ubuntu, install them with `sudo apt-get install clang lld make`.
No libc or WASI SDK is needed.

```sh
make -C plugins/vxlan.c            # -> out/bin/vxlan.c.wasm
go test -v -exec sudo -race ./pkg/plugin -run TestVXLANCPluginIntegration
```

The build creates `out/bin` if needed.
Set `CLANG` to select another compiler, for example `make -C plugins/vxlan.c CLANG=clang-19`.
The top-level `make build-plugins` also builds this plugin alongside the Go and TinyGo plugins.
If clang or `wasm-ld` is missing, it prints a warning and skips only the C plugin.
A compiler or linker error still fails the build.
The direct `make -C plugins/vxlan.c` command requires both tools and fails if either is missing.

To build in Docker without installing the tools on the host:

```sh
docker run --rm -v "$PWD:/w" -w /w debian:trixie-slim sh -c \
  'apt-get update -qq && apt-get install -y -qq clang lld make >/dev/null && make -C plugins/vxlan.c'
```

Run these commands from the repository root.
The integration test skips when `out/bin/vxlan.c.wasm` is absent.
CI installs clang and lld and builds the plugin before running the test suite, so this test runs in CI.

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
