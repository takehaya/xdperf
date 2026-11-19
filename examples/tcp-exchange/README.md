# TCP request/response rounds

After `make build`, run:

```bash
sudo ./examples/tcp-exchange/setup.sh
sudo ./examples/tcp-exchange/test.sh
sudo ./examples/tcp-exchange/teardown.sh
```

Always run teardown after a failed test as well, or use `sudo ./examples/run_all.sh`.

The sender runs `tcpflow.go` with request/response fields, and the peer is
`xdperf-sink -respond` (kernel TCP) behind a pass-through XDP program. Each case
compares the sender's `tcp final statistics` with the sink's JSON summary:

| Case | Plugin fields | Sink | Checked |
| --- | --- | --- | --- |
| `rounds` | `bytes 1000`, `response_bytes 4000`, `rounds 10` | `-respond 1000:4000` | 80 rounds, 320,000 response bytes, 80,000 request bytes |
| `download` | `bytes 0`, `response_bytes 1000000` | `-respond 0:1000000` | one round per flow, no request bytes |
| `until-fin` | `bytes 1000`, `response_until_fin` | `-respond 1000:65536 -close-after 1` | the response ends at the sink's FIN |
| `server-close` | `rounds 10`, `close server` | `-respond 1000:4000 -close-after 10` | the same counts as `rounds` after the sink closes |
| `duration` | `rounds 0`, `--duration 3s` | `-respond 1000:4000` | more than 10 rounds per flow, and the sink's response count equals `rounds_done` |
| `early-close` | `rounds 10` | `-respond 1000:4000 -close-after 3` | `peer_closed_early` for every flow in the log and in `--summary-json`, and a non-zero exit |

Every case uses 8 flows (`FLOWS`), a window of 16 segments (`WINDOW`) and one
worker, and requires no `respond_errors` from the sink. Logs are
`/run/xdperf-examples/xchg-<case>-{tx,sink}.log`. `CASES` selects a subset,
for example `CASES="rounds download" sudo ./examples/tcp-exchange/test.sh`.
See the [plugin README](../../plugins/tcpflow.go/README.md#requestresponse-rounds)
for the fields and the [TCP stream guide](../../docs/ja/tcp_stream.md) for the
statistics.
