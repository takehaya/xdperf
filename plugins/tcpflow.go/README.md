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
| `cps` | `0` | Target initial connection attempts/second; zero uses closed-loop replenishment |
| `port_reuse_delay_ms` | `60000` | Quarantine after DONE/FAILED; zero uses the default, explicit values must be at least `1000` |
| `bytes` | `"65536"` | Bytes per connection as a uint64 decimal string; `"0"` requires `--count` or `--duration` |

Zero or omitted tuning fields use the defaults below.

| Field | Default | Meaning |
| --- | --- | --- |
| `window_segs` | 32 | Maximum segments in flight per flow, 1..65535 |
| `mss` | automatic | MSS before subtracting TCP data options, 64..65535; automatic sizing respects MTU/frame limits |
| `rto_ms` | 200 | Positive retransmission timeout in milliseconds |
| `ip_id` | `flow` | IPv4 ID mode: `flow` or `shared`; empty uses the default |
| `port_base` | 10000 | First source port for the entire set; repetition cycles through ports up to 65535 |

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

Repetition uses a fixed pool of `65536 - port_base` port states (55,536 at the default base).
Each slot owns a disjoint sequence of ports and cycles through it after DONE or FAILED, waiting for quarantine expiry when needed.
Valid retransmitted FINs on DONE entries are ACKed and extend the quarantine.
State memory is bounded by the port pool, even when the attempt limit exceeds its capacity.
Slots do not borrow ports from other slots; a quarantine wait does not imply global port exhaustion.
If `flows` exceeds the pool size in a reuse configuration, the effective concurrency is reduced to the pool size.

The quarantine exists only during a run.
Use a dedicated netns and a fresh port range or source IP between runs to avoid old tuples and host port conflicts.
Reserving `ip_local_reserved_ports` prevents automatic allocation but cannot prevent explicit binds.
The concurrency limit does not bound peer TIME_WAIT or LB conntrack entries.
Shorter quarantine values require validation against delayed traffic and the peer or CT/NAT state on the path.

A positive `cps` requires `connections` and rejects `--pps`.
Workers share the start/end clock and stagger initial SYN opportunities; retransmissions, data and FIN continue independently.
Each worker can use at most one outstanding opportunity.
Missed opportunities are discarded without consuming the attempt limit or extending duration; workers never catch up with a burst.
With connection lifetime L and quarantine H in seconds, the sustainable rate is approximately at most `pool_size / (H + L)`.

```bash
sudo out/bin/xdperf run --device eth0 --plugin tcpflow.go --plugin-path out/bin \
  --parallelism 2 --duration 120s --summary-json cps.json \
  --cfg '{"dst_ip":"192.0.2.2","flows":128,"bytes":"1024","connections":0,"cps":3000,"port_reuse_delay_ms":10000}'
```

Periodic output reports achieved start, establishment, and completion CPS from counter deltas and actual elapsed time.
Final CPS covers the load period; load and drain/linger durations are logged separately with the stop reason.
`started` counts connections whose first SYN was successfully built; `syn_sent` includes retransmissions.
Counters remain cumulative across reuse.
`slots_in_use` and `peak_slots_in_use` include SYN_SENT through FIN_WAIT and exclude quarantined terminal entries.
The final log and summary JSON include `target_cps`, `port_reuses`, `start_opportunities`, `start_permits`, `cps_unmet`, and `start_dropped_late`, `start_dropped_busy`, `start_dropped_quarantine`, `start_dropped_scan`, `start_dropped_service`.
These drop reasons distinguish worker delay, busy owned slots, quarantine waits, the eight-slot scan limit and iterations reserved for existing connections.
After each new SYN, at least one iteration services data, retransmissions or FIN; a separate SYN cursor preserves normal round-robin order.
`port_exhausted` remains false because repetition waits for quarantine expiry.
CSV remains available for finite attempts within the port capacity, with the connection number in `flow`.
`--tcp-flow-report` is rejected when reuse is possible (`connections: 0` or a limit above port capacity), since retained states cannot preserve the complete CSV history.
Source-IP `variable_params` are rejected with positive CPS or possible reuse.
Failure exit behavior for summary JSON remains unchanged.
