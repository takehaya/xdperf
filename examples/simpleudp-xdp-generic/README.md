# simpleudp-xdp-generic — UDP send/receive with forced generic (SKB) mode

Runs the [simpleudp](../simpleudp/README.md) scenario with `--xdp-mode generic`
on both the sender and the receiver. Verifies that:

- the receiver attaches in generic (SKB) mode (`xdpgeneric` in `ip -d link`)
- send/receive still works end to end in generic mode

This exercises the `--xdp-mode` flag added for environments where native XDP
attach fails (e.g. veth in ContainerLab topologies); the default `auto` mode
falls back to generic automatically in that case.

Unlike a native attach, generic mode does not activate the veth peer's NAPI,
so `setup.sh` additionally enables GRO on the receiver device — otherwise the
veth XDP transmit path silently drops every frame (see
[simpleudp-no-rx-attach](../simpleudp-no-rx-attach/README.md) for the kernel
background).

Topology and usage are otherwise the same as [simpleudp](../simpleudp/README.md).

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## Additional parameters (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `XDP_MODE` | `generic` | `--xdp-mode` value passed to both sides |

Other parameters are shared with simpleudp.
