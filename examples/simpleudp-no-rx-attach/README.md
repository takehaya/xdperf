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

## Why GRO works without XDP (kernel background)

Since v5.13, veth's XDP transmit path checks whether the peer's **NAPI** is
active rather than whether an XDP program is attached, and the GRO feature
flag doubles as the switch that enables NAPI mode without XDP:

- [`d3256efd8e8b` "veth: allow enabling NAPI even without XDP"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d3256efd8e8b) —
  `ethtool -K <dev> gro on` enables veth NAPI mode even with no XDP program
- [`0e672f306a28` "veth: check for NAPI instead of xdp_prog before xmit of XDP frame"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0e672f306a28) —
  `veth_xdp_xmit` checks `rq->napi`, so a veth can receive XDP-transmitted
  frames (XDP_REDIRECT / `ndo_xdp_xmit`) without loading an XDP program on
  the peer

Note what "works" means here: with GRO on (and no XDP program), frames are
delivered to the peer's **normal network stack** (counted by `rx_packets`),
not to an XDP program. Practically, this means that when the receiving end
of a veth is not running an XDP application (e.g., a plain UDP app or a
DUT), enabling GRO on the receiver veth is enough for XDP-generated traffic
to arrive — a veth-specific caveat that physical NICs don't have.

## Run

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

Parameters are shared with [simpleudp](../simpleudp/README.md).
