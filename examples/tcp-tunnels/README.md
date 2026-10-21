# TCP tunnel interoperability

After `make build`, run:

```bash
sudo ./examples/tcp-tunnels/setup.sh
sudo ./examples/tcp-tunnels/test.sh
sudo ./examples/tcp-tunnels/teardown.sh
```

Always run teardown after a failed test as well, or use `sudo ./examples/run_all.sh`.

The scenario sends mixed packet/TCP traffic through Linux GRE (key/no key),
gretap, ip6gre, IPIP/SIT, ip6tnl, SRv6, MPLS, and GTP-U endpoints.
It checks four completed flows and 77,830 received/ACKed bytes per case,
with both inner IPv4 and IPv6 (22 cases before kernel-dependent skips).
The ordered byte targets are `[4097, 4097, 4097, 65539]`, the sink must accept
and close four connections, and both `rx_tuple_mismatch` and `rx_invalid_tcp`
must be zero. Configuration and report checks live in [common/py](../common/py/).

SRv6 sends one segment and receives one segment, two segments, or a bare IP
reply. Linux End.DX4 and End.DT6 (local table 255) terminate the inbound
encapsulation; a seg6 lwtunnel route constructs return traffic.
MPLS uses `mpls_router` to pop the inbound label and an MPLS lwtunnel route
for replies. GTP-U uses kernel-owned UDP sockets and a small generic-netlink
helper to install the PDP context; no GTP daemon or Python package is needed.
IPv6 GRE/IPIP endpoints use `encaplimit none` because generic IPv6 Destination
Options are outside the supported receive formats.

`TUNNEL_CASES` and `INNER_CASES` can restrict cases, for example:

```sh
sudo env TUNNEL_CASES='srv6-two mpls' INNER_CASES=6 ./examples/tcp-tunnels/test.sh
```

Missing kernel modules/SEG6 support or unavailable kernel-owned GTP sockets
are reported as individual skips. If all cases are skipped, the script returns
3 (the examples runner's SKIP code). Configured traffic failures remain errors.
`TestTCPReceiveTunnels` provides BPF_PROG_RUN coverage independent of these
kernel devices, including GTP-U extension chains and malformed inputs.
