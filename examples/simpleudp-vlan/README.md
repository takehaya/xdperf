# simpleudp-vlan — UDP send/receive with an outer 802.1Q VLAN tag

Sends UDP packets tagged with an outer 802.1Q header via the simpleudp
plugin's `vlan_id` option across a veth pair, and verifies that the receiver
XDP program's counter (`xdp_rx` strips 802.1Q/QinQ tags before parsing
IPv4/IPv6) matches the number of packets sent.

Topology and usage are the same as [simpleudp](../simpleudp/README.md).

```bash
sudo ./setup.sh
sudo ./test.sh
sudo ./teardown.sh
```

## Additional parameters (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `VLAN_ID` | `100` | 802.1Q VLAN ID (1-4094) |
| `VLAN_PCP` | `3` | 802.1Q priority (0-7) |

Other parameters are shared with simpleudp.
