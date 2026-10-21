# TCP flow templates

After `make build`, run:

```bash
sudo ./examples/tcp-template/setup.sh
sudo ./examples/tcp-template/test.sh
sudo ./examples/tcp-template/teardown.sh
```

Always run teardown after a failed test as well, or use `sudo ./examples/run_all.sh`.

The `mixed.go` plugin accepts `tcp_base`, an Ethernet frame ending at the
fixed TCP header. `syn_options` and `data_options` contain base64-encoded
static options. The plugin maps the frame to the `tcp_flow` variant's
`base_packet`; the host derives the destination from that template.

Six cases cover IPv4/IPv6 with untagged, VLAN and QinQ frames. Each checks
four completed flows, ordered byte targets `[4097, 4097, 4097, 65539]`, and
four accepted and closed sink connections totaling 77,830 bytes. SYN packets
include SACK-Permitted, data packets include NOP options, and templates set
DSCP, TTL and the IPv6 flow label. `TestTCPTemplateBPF` independently checks
header preservation and checksums.

Setup creates the veth/VLAN/QinQ topology. The test uses the shared
[configuration generator and report checks](../common/py/).
