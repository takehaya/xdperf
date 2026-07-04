# simpleudp-no-rx-attach — what happens WITHOUT an XDP program on the peer

A negative-case scenario that measures the veth XDP transmit path when the
receiver side has **no** XDP program attached. On veth, `ndo_xdp_xmit`
silently drops frames unless the peer's NAPI is active — which requires
either an XDP program attached on the peer or GRO enabled. See
[XDP ate my packets](https://fedepaol.github.io/blog/2023/09/11/xdp-ate-my-packets-and-how-i-debugged-it).

The test verifies both sides of the mechanism:

| Phase | Receiver state | Expectation |
|-------|----------------|-------------|
| 1 | no XDP attach, GRO off | ~0 packets arrive (silently eaten) |
| 2 | no XDP attach, GRO **on** | packets reach the normal network stack (counted via `rx_packets`) |

Together with [simpleudp](../simpleudp/README.md) (peer XDP attached →
everything arrives), this pins down the exact requirement: the veth XDP TX
path needs peer NAPI (XDP program or GRO), and that is why the examples
always start the receive server before transmitting.

## Run

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

Parameters are shared with [simpleudp](../simpleudp/README.md).
