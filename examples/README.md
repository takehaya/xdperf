# examples — veth-based local end-to-end tests

Self-contained example scenarios that connect two network namespaces with a
veth pair, send with xdperf on one side and receive on the other, and verify
the result with **real counters**. No physical NIC or VM required — runs on a
single Linux host (including CI ubuntu runners).

For verification closer to a real NIC path with QEMU 2-VM, see
[scripts/vmlab](../scripts/vmlab/README.md).

## Prerequisites

- Linux kernel 5.18+ (XDP live-frames required; automatically SKIPs on
  unsupported kernels)
- root privileges (for netns / veth / eBPF operations)
- `iproute2`, `ethtool`
- `make build` done at the repository root (`out/bin/xdperf` and `*.wasm`)

## Usage

```bash
make build

# Run all scenarios at once
sudo ./examples/run_all.sh
# or
make examples

# Run a single scenario
cd examples/simpleudp
sudo ./setup.sh && sudo ./test.sh && sudo ./teardown.sh
```

## Scenarios

| Scenario | Description |
|----------|-------------|
| [simpleudp](simpleudp/) | Basic UDP send/receive. Verifies rx counter == packets sent |
| [simpleudp-vlan](simpleudp-vlan/) | UDP with an outer 802.1Q tag. Verifies counting through VLAN parsing |

## How it works

```
ns: xdperf-tx                      ns: xdperf-rx
+------------------+   veth pair  +------------------+
| xdp-tx           |==============| xdp-rx           |
| 192.168.100.1/24 |              | 192.168.100.2/24 |
| live-frames TX   |              | xdp_rx attach    |
+------------------+              +------------------+
```

- The sender does not attach XDP to the device; it transmits from the veth via
  `BPF_PROG_RUN` live-frames
- The receiver attaches the `xdp_rx` program, which counts IPv4/IPv6 frames and
  DROPs them
- The veth XDP TX path requires an XDP program attached on the peer, so the
  **receive server is started first**
- Verification uses the delta of the receiver veth's `ethtool -S` counters
  (sum of `rx_queue_N_xdp_packets`)
- IPv6 is disabled during setup (kernel-originated IPv6 frames would otherwise
  break the exact-match comparison)

## Adding a new scenario

Put a directory containing `test.sh` directly under examples/ and
`run_all.sh` will pick it up. `setup.sh` / `teardown.sh` are optional (run
before/after if present). Source the helpers in [common/](common/)
(`udp_scenario.sh` etc.) for shared logic.
