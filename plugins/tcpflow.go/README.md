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
| `bytes` | `"65536"` | Bytes per connection as a uint64 decimal string; `"0"` requires `--count` or `--duration` |

Zero or omitted tuning fields use the defaults below.

| Field | Default | Meaning |
| --- | --- | --- |
| `window_segs` | 32 | Maximum segments in flight per flow, 1..65535 |
| `mss` | automatic | MSS before subtracting TCP data options, 64..65535; automatic sizing respects MTU/frame limits |
| `rto_ms` | 200 | Positive retransmission timeout in milliseconds |
| `ip_id` | `flow` | IPv4 ID mode: `flow` or `shared`; empty uses the default |
| `port_base` | 10000 | First source port for the entire set; all flows must fit through port 65535 |

The host uses the largest group RTO for linger and drain timeout.
Retry counts remain engine constants.

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
  --tcp-flow-report flows.csv \
  --cfg '{"dst_ip":"192.0.2.2","tcp_port":5201,"flows":4,"bytes":"65536","window_segs":8,"mss":1024,"port_base":12000}'
```

For a veth peer, run the sink as root with `-xdp-pass-dev <peer-veth>` so it can receive XDP traffic.
TCP replies are handled automatically; `--recv` is unnecessary.
The sink prints connection and byte totals on exit (Ctrl-C).

Finite TCP-only sets need neither `--count` nor `--duration`; they finish when all flows complete.
`--count N` limits TX worker frames, including SYN, data, FIN, retransmissions, probes, and RST.
RX replies and idle/build failures do not consume this budget.
All flows can finish before the limit.
At the limit, the sender skips drain, lingers for 2×RTO, and warns about unfinished flows; the exit status is 0 unless a flow failed.
To stream for a fixed duration, add `--duration 10s` and set `"bytes":"0"`; TCP-only duration needs no PPS.
Count and duration cannot be explicitly combined.

Standalone `--tcp` has been removed; use this plugin to send TCP flows.
See the [variant guide](../../docs/ja/mixed_variants.md) for SDK details.
