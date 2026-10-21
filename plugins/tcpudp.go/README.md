# UDP and TCP with tcpudp.go

This Go Wasm plugin returns one fixed IPv4/UDP packet variant and one TCP variant containing a single 65,536-byte flow.
The two weights allocate TX iterations; they do not guarantee packet or byte ratios.
The host resolves the TCP route and neighbor independently of the UDP frame's source IP and destination MAC.

## Configuration

Pass these fields as JSON with `--cfg`:

| Field | Default | Meaning |
| --- | --- | --- |
| `src_ip` | `192.168.110.1` | Source IPv4 address for UDP |
| `dst_ip` | `192.168.110.2` | Destination IPv4 address for UDP and TCP |
| `dst_mac` | `02:00:00:00:00:02` | Destination MAC for UDP |
| `udp_port` | `5201` | Destination UDP port; source port is fixed at 53000 |
| `tcp_port` | `5201` | Destination TCP port |
| `packet_weight` | `3` | Positive weight for UDP TX iterations |
| `tcp_weight` | `1` | Positive weight for TCP TX iterations |

UDP carries 32 zero bytes.
TCP sends 65,536 bytes on one connection; edit `TCPFlow.Flows` in `main.go` to change this example.
For configurable TCP flow counts and sizes, see [tcpflow.go](../tcpflow.go/).

## Run

Build from the repository root:

```bash
make build
```

On the peer, start a sink for both protocols on port 5201:

```bash
out/bin/xdperf-sink -proto both -listen 192.0.2.2:5201
```

On the sender, adjust the IP addresses, MAC, and device:

```bash
sudo out/bin/xdperf run --device eth0 --plugin tcpudp.go --plugin-path out/bin \
  --duration 10s --pps 2000 --tcp-flow-report flows.csv \
  --cfg '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02","packet_weight":3,"tcp_weight":1}'
```

For a veth peer, run the sink as root with `-xdp-pass-dev <peer-veth>`.
The sink counts TCP connections/bytes and received UDP packets/bytes, and prints totals on exit (Ctrl-C).
If `udp_port` differs from `tcp_port`, run a separate `xdperf-sink -proto udp -listen <ip>:<udp_port>` for UDP.
To count UDP replies at the sender, use a UDP echo server and add `--recv`; the sink only counts incoming UDP.
TCP replies are handled regardless of `--recv`.

Currently, when a response includes `tcp_flow`, `--count` only sets the Diff pool size and does not limit transmitted frames, including UDP packets.
The run ends at the earliest of the TCP flow completing, `--duration` expiring, or a signal starting drain.
UDP stops during drain, and the sender closes TCP.
The CLI still requires `--count` or `--duration`.

The standalone `--tcp` mode sends TCP using CLI flags without a plugin.
This example supplies both variant types from Wasm, so omit `--tcp`, `--tcp-dst`, `--tcp-flows`, and `--tcp-bytes`.
See the [variant guide](../../docs/ja/mixed_variants.md) for SDK details.
