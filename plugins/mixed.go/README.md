# Mix UDP and TCP flows with mixed.go

This Go Wasm plugin returns DNS-format UDP queries and four TCP flows with different transfer sizes.
Omit `--tcp`.

```bash
make build
sudo out/bin/xdperf run --device eth0 --plugin mixed.go --plugin-path out/bin \
  --duration 10s --pps 2000 --tcp-flow-report flows.csv \
  --cfg '{"src_ip":"192.0.2.1","dst_ip":"192.0.2.2","dst_mac":"02:00:00:00:00:02"}'
```

The peer needs a TCP sink listening on port 5201.
To count UDP replies too, use `--recv` and a UDP echo server on the peer.
The plugin supplies connection counts and byte targets, so omit `--tcp-dst`, `--tcp-flows`, and `--tcp-bytes`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `src_ip` / `dst_ip` | `192.168.110.1` / `192.168.110.2` | UDP IPv4 addresses; when tcp_base is omitted, dst_ip is also the TCP destination |
| `dst_mac` | `02:00:00:00:00:02` | UDP frame destination MAC |
| `udp_port` / `tcp_port` | `5353` / `5201` | UDP port and default TCP destination port |
| `small_bytes` / `large_bytes` | `"65536"` / `"67108864"` | Transfer sizes for the first three flows and the last flow, as uint64 decimal strings |
| `packet_weight` / `tcp_weight` | `3` / `1` | Packet and TCP TX iteration weights |
| `tcp_base` | None | SDK base_packet; data is base64, and length extends through the fixed TCP header |
| `tcp_encapsulation` | None | Fixup tables passed to SDK tcp_flow.encapsulation |
| `syn_options` / `data_options` | None | Fixed TCP options in base64 |
| `timestamps` | `false` | Offer TCP Timestamps and use them after negotiation |
| `payload_pattern` | None | Repeated base64 pattern of at most 256 bytes |
| `flow_variable_params` | None | SDK variant-level variable_params; vary the inner source IP of an explicit tcp_base per flow |

With `tcp_base`, the TCP destination comes from its inner header.
Otherwise, the host resolves the route and neighbor for `dst_ip:tcp_port`.
`src_ip` and `dst_mac` configure the UDP packet and do not override TCP route resolution.
The sample UDP packet uses IPv4 only.
For TCP over IPv6, supply an IPv6 `tcp_base` and keep the UDP addresses as IPv4.

Currently, when a response includes `tcp_flow`, `--count` only sets the Diff pool size and does not limit transmitted frames, including UDP packets.
The run ends at the earliest of all TCP flows completing, `--duration` expiring, or a signal starting TCP drain.
The CLI still requires `--count` or `--duration`.
Weights do not guarantee actual frame or byte ratios.
See the [mixed traffic guide](../../docs/ja/mixed_variants.md) for SDK JSON, tunnel limits, startup time, and RX diagnostics.

Working examples cover [mixed traffic](../../examples/mixed/test.sh), [TCP templates](../../examples/tcp-template/README.md), [VXLAN](../../examples/tcp-vxlan/README.md), [tunnels](../../examples/tcp-tunnels/README.md), and [payloads](../../examples/tcp-payload/README.md).
