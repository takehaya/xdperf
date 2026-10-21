# TCP flow options and payloads

After `make build`, run:

```bash
sudo ./examples/tcp-payload/setup.sh
sudo ./examples/tcp-payload/test.sh
sudo ./examples/tcp-payload/teardown.sh
```

Always run teardown after a failed test as well, or use `sudo ./examples/run_all.sh`.

Twelve cases cover IPv4/IPv6 with timestamp negotiation, declined timestamps,
a three-byte repeating payload, per-flow source IPs, all features combined,
and combined features under 5% ACK loss. The Linux TCP receiver in `sink.py`
checks every byte against its stream position, across receive boundaries,
and requires stream lengths `[4097, 4097, 4097, 65539]`. The shared report
checker requires four completed flows, 77,830 acknowledged bytes and zero
`rx_tuple_mismatch` and `rx_invalid_tcp`. BPF_PROG_RUN tests independently
check retransmission offsets and checksums.

The `mixed.go` configuration uses `timestamps: true`, base64 `payload_pattern`
and `flow_variable_params`. Variable offsets start at the Ethernet frame;
currently only inner source IP ranges are accepted. Setup adds the per-flow
source addresses. See the [design](../../docs/ja/design_tcp_flow_template.md)
and the shared [configuration generator and report checks](../common/py/).
