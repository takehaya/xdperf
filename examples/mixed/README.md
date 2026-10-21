# Mixed UDP packets and TCP flows

After `make build`, run:

```bash
sudo ./examples/mixed/setup.sh
sudo ./examples/mixed/test.sh
sudo ./examples/mixed/teardown.sh
```

Always run teardown after a failed test as well. `sudo ./examples/run_all.sh`
runs setup, test and teardown for every scenario automatically.

The `mixed.go` plugin combines DNS-style UDP packets with three small TCP
flows and one large flow. Both finite and duration modes run with one and
two workers (`MIXED_CASES` and `MIXED_WORKERS` select subsets).

An independent UDP echo checks the DNS header and name, counts packets and
returns each packet. The test compares its count with both packet TX and RX,
and compares the kernel TCP sink's connections and bytes with the flow CSV.
Finite flows must acknowledge 65,536 bytes each for the three small flows and
262,144 bytes for the large flow. Duration mode uses 4,097-byte small flows
and requires positive progress from the unlimited large flow.

The checks also cover CSV flow order and completion, TCP packet accounting,
zero receive/dispatch errors, positive drain opportunities, a TCP opportunity
share within 0.03 of 0.25, and the actual TCP TX ratio within `1e-6`.
The opportunity share describes scheduling iterations, rather than a packet
or byte ratio. See the [mixed variants guide](../../docs/ja/mixed_variants.md).

The scenario uses [shared lifecycle helpers](../common/tcp_plugin_scenario.sh)
and standard-library Python CLIs in [common/py](../common/py/).
