# TCP flows inside VXLAN

After `make build`, run:

```bash
sudo ./examples/tcp-vxlan/setup.sh
sudo ./examples/tcp-vxlan/test.sh
sudo ./examples/tcp-vxlan/teardown.sh
```

Always run teardown after a failed test as well, or use `sudo ./examples/run_all.sh`.

Linux VXLAN devices terminate the tunnel in both namespaces. xdperf uses a
plugin-provided outer Ethernet/IP/UDP/VXLAN and inner Ethernet/IP/TCP template;
`xdperf-sink` receives the inner TCP streams. xdperf parses returning VXLAN
frames in XDP and matches the inner tuple.

Six cases combine IPv4/IPv6 inner packets with IPv4 outer UDP zero/LCO
checksums or IPv6 outer LCO checksums. Each case clears inner neighbors first
and enables `--recv`, verifying that ARP/ND still reaches the host. Each checks
four completed flows, ordered byte targets `[4097, 4097, 4097, 65539]`, and
four accepted and closed sink connections totaling 77,830 bytes. UDP source
ports vary by flow, starting at 49152. `tcp_encapsulation` is the sample
plugin's configuration name for the SDK's `tcp_flow.encapsulation`.

`TestTCPEncapBPF` covers GENEVE, nested VXLAN, the 256-byte limit and transmit
updates for IPIP/GRE/SRv6/GTP-U/MPLS. Linux interoperability for those other
tunnels and asymmetric replies is covered by [tcp-tunnels](../tcp-tunnels/README.md).
See the [mixed variants guide](../../docs/ja/mixed_variants.md) for supported
formats and limits. Configuration and report checks live in [common/py](../common/py/).
