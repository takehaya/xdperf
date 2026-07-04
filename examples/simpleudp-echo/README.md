# simpleudp-echo — XDP_TX echo round-trip over veth

Runs the receiver as an echo server (`--swap-resp`): the `xdp_rx` program
swaps MAC/IP addresses and returns the packet with `XDP_TX`. The sender runs
in send+receive mode (`--recv`) and counts the echoed packets coming back.
Both directions are asserted via `ethtool -S` XDP counter deltas.

## What this verifies (the veth XDP_TX gotcha)

On veth, a packet sent with `XDP_TX` is **silently dropped unless the peer
device also has an XDP program attached** — a well-known pitfall described in
[XDP ate my packets](https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it).

xdperf guards against this by attaching a program to its own device while
sending (`xdp_pass_dummy`, or `xdp_rx` in send+receive mode — see
`runTXPacket` in `pkg/xdperf/xdperf.go`). This scenario exercises exactly
that return path end-to-end:

```
ns: xdperf-tx                        ns: xdperf-rx
+-------------------+   veth pair   +-------------------+
| xdp-tx            |===============| xdp-rx            |
| live-frames TX  --|--------------->-- xdp_rx counts   |
| xdp_rx counts   --<---------------|-- XDP_TX (echo)   |
+-------------------+               +-------------------+
```

If the sender-side attach were missing, the echo counter would read ~0 and
the test would FAIL.

## Run

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## Additional parameters (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `ECHO_THRESHOLD` | `99` | Echo receive rate (%) required to PASS. Echoes arriving after the sender exits (XDP detached) are not counted, so a small race margin is allowed |

Other parameters are shared with [simpleudp](../simpleudp/README.md).
