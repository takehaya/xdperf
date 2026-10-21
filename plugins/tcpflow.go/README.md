# TCP flows with tcpflow.go

This Go Wasm plugin returns one `tcp_flow` variant and sends no UDP packets.
The host builds the TCP template using its route and neighbor tables.

## Configuration

Pass these fields as JSON with `--cfg`:

| Field | Default | Meaning |
| --- | --- | --- |
| `dst_ip` | `192.168.110.2` | Destination IP literal (IPv4 or IPv6) |
| `tcp_port` | `5201` | Destination TCP port |
| `flows` | `4` | Number of connections; each uses a distinct source port |
| `bytes` | `"65536"` | Bytes per connection as a uint64 decimal string; `"0"` requires `--duration` |

## Run

Build from the repository root:

```bash
make build
```

On the peer, start the TCP sink:

```bash
out/bin/xdperf-sink -listen 192.0.2.2:5201
```

On the sender, use an interface with a route to the peer:

```bash
sudo out/bin/xdperf run --device eth0 --plugin tcpflow.go --plugin-path out/bin \
  --duration 10s --pps 2000 --tcp-flow-report flows.csv \
  --cfg '{"dst_ip":"192.0.2.2","tcp_port":5201,"flows":4,"bytes":"65536"}'
```

For a veth peer, run the sink as root with `-xdp-pass-dev <peer-veth>` so it can receive XDP traffic.
TCP replies are handled automatically; `--recv` is unnecessary.
The sink prints connection and byte totals on exit (Ctrl-C).

Currently, when a response includes `tcp_flow`, `--count` only sets the Diff pool size and does not limit transmitted frames.
The run ends at the earliest of all TCP flows completing, `--duration` expiring, or a signal starting TCP drain.
The CLI still requires `--count` or `--duration`.
To stream until the duration expires, set `"bytes":"0"` in the example above.

The standalone `--tcp` mode creates flows from CLI flags without a plugin.
This example supplies them from Wasm, so omit `--tcp`, `--tcp-dst`, `--tcp-flows`, and `--tcp-bytes`.
See the [variant guide](../../docs/ja/mixed_variants.md) for SDK details.
