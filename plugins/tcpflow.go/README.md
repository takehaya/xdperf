# TCP flows with tcpflow.go

This Go Wasm plugin returns one `tcp_flow` variant and sends no UDP packets.
The host builds the TCP template using its route and neighbor tables.
Routes through an 802.1Q VLAN child add its tag with PCP 0.
Automatic 802.1ad routes are rejected; use a plugin returning `base_packet` for other VLAN protocols.

## Configuration

Pass these fields as JSON with `--cfg`:

| Field | Default | Meaning |
| --- | --- | --- |
| `dst_ip` | `192.168.110.2` | Destination IP literal (IPv4 or IPv6) |
| `tcp_port` | `5201` | Destination TCP port |
| `flows` | `4` | Number of flows, or concurrent slots with `connections` |
| `connections` | omitted | Total connection attempts; `0` requires `--duration` |
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

## Repeat connections

Add `"connections":1000` to attempt 1,000 connections in total, using `flows` as the concurrency limit:

```bash
sudo out/bin/xdperf run --device eth0 --plugin tcpflow.go --plugin-path out/bin \
  --parallelism 1 --tcp-flow-report connections.csv \
  --cfg '{"dst_ip":"192.0.2.2","flows":4,"bytes":"1024","connections":1000}'
```

Omitting `connections` preserves one connection per flow.
A positive value includes failed attempts; `0` requires `--duration` and keeps starting connections until it expires.
Each slot repeats its byte target and template after the previous connection finishes or fails.
Duration and signals stop new starts and drain existing connections.
Repetition requires a single TCP variant and rejects packet mixtures, multiple TCP variants, unlimited bytes (`"0"`), and `--count`.

Connection j uses source port `port_base + j`; ports never wrap and old states remain until exit.
Capacity is `65536 - port_base` (55,536 connections at the default base).
Larger finite requests are rejected before transmission; exhaustion during a duration run drains and exits with `port_exhausted`.
Use a dedicated netns and a fresh port range or source IP between runs to avoid old tuples and host port conflicts.
Reserving `ip_local_reserved_ports` prevents automatic allocation but cannot prevent explicit binds.
The concurrency limit does not bound peer TIME_WAIT or LB conntrack entries.

Periodic output reports achieved start, establishment, and completion CPS from counter deltas and actual elapsed time.
Final CPS covers the load period; load and drain/linger durations are logged separately with the stop reason.
`started` counts connections whose first SYN was successfully built; `syn_sent` includes retransmissions.
In repetition mode, CSV contains one row per started connection, with its connection number in `flow`.
This mode replenishes connections on completion; it does not impose a target CPS, and `--pps` is not a CPS control.
