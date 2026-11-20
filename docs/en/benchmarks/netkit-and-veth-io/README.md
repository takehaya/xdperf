# Benchmarking `veth`, `netkit`, and Kubernetes / Cilium Datapaths with `xdperf`

> **Japanese version (日本語版)**: [docs/ja/benchmarks/netkit-and-veth-io/README.md](../../../ja/benchmarks/netkit-and-veth-io/README.md)

## Summary

`veth` and `netkit` are the virtual devices that connect containers and Kubernetes Pods to the host. This document records the transmit rate of `xdperf`, an XDP-based traffic generator, the difference between `veth` and `netkit-bpf` measured under `xdperf` load, and how to set up the test environment.

1. **On a `veth` pair, `xdperf` transmits 5.4x to 22x faster than the seven other transmit mechanisms (Section 1)**. With one sender core and 64 B UDP, `xdperf` reached 9.56 Mpps and the runner-up, `AF_XDP` in copy mode, reached 1.78 Mpps. The other seven (`AF_XDP`, `io_uring`, three `AF_PACKET` variants, the kernel's `pktgen`, and a UDP socket) allocate an `sk_buff` for every packet. `xdperf` allocates none and recycles frames inside the kernel. The seven mechanisms that allocate an `sk_buff` stayed below 1.8 Mpps per core on both `veth` (mean of five runs) and `netkit`.
2. **Switching the receiving Pod's connection from `veth` to `netkit-bpf` raised TCP throughput by up to 35% (Section 2)**. `netkit-bpf` is `netkit` combined with BPF forwarding programs (`bpf_redirect_peer` and others). The `veth` baseline uses kernel forwarding. This document does not report `netkit` without the BPF programs. The size of the gain depends on how much GRO coalesces segments, because coalescing means fewer packets cross the Pod boundary. With `iperf3 -P 4` the gain was +4% (±2.9 pt), about the size of the run-to-run variation. `xdperf` can raise the flow count or set `ip_id: "shared"` on the sender, either of which limits GRO coalescing without any change on the receiver. Measured with `xdperf`, the gain was +16% to +32% on a single host with 16 to 256 flows (mean of five runs). On physical NICs each condition was run once: +1% to +35% on 100GbE and +5% to +10% on 400GbE. Short-lived TCP connections per second (CPS) rose 46% on 400GbE and 3% on 100GbE.
3. **Adding per-flow (5-tuple) counters to the BPF programs on the receive path lowered throughput by no more than the run-to-run variation (Section 2)**. The counters live in an `LRU_HASH` map (65,536 entries). Where GRO did not coalesce segments, every flow's count matched `xdperf`'s per-flow send record (`--tcp-flow-report`).
4. **To test `netkit`, send from `xdperf` on `veth` or a physical NIC and swap only the receiving Pod's connection between `veth` and `netkit` (Section 3)**. `xdperf` cannot transmit directly on `netkit`, because `netkit` does not implement XDP frame transmission (`.ndo_xdp_xmit`). Section 3 shows this setup for a single host, two physical nodes, and Kubernetes + Cilium. The quick reference matrix in Section 3.3 lists the settings Cilium needs.
5. **On `veth`, `xdperf`'s transmit rate grows almost in proportion to the number of queues and workers (Section 3.4)**. A worker is an `xdperf` transmit thread that uses one core. With 32 queues and 32 workers on a single host, `xdperf` reached 301.5 Mpps for 64 B UDP and 225.7 Gbps for TCP. The TCP peer was `xdperf`'s XDP responder (`--tcp-server`), and there were no retransmissions. A `veth` created by a CNI has one active queue, but the count can be raised with `ethtool -L` after creation (confirmed on a `veth` pair created with one queue). If the Pod has a CPU limit, keep the worker count within it, pass the allowed CPUs explicitly with `--cpu-mode`, and choose a queue count in which the CPU numbers do not collide. Otherwise `xdperf` either fails to start or its transmit rate falls to between a quarter and a sixteenth.

The measurements come from three environments: a single host (Xeon 6746E, 64 vCPU), two 100GbE nodes (ConnectX-5, EPYC 7282), and two 400GbE nodes (ConnectX-7, Core i9-12900K).

## Contents

This document covers:
1. **8-Way Linux Packet Transmission Comparison on `veth` and `netkit` (`n=5`, [veth_io_summary.csv](../../../ja/benchmarks/netkit-and-veth-io/veth_io_summary.csv)) (Section 1)**:
   - Empirical 1-core comparison of `xdperf` (`BPF_F_TEST_XDP_LIVE_FRAMES` + in-kernel XDP Diff) against `AF_XDP` (`XDP_COPY`), `io_uring` (`IORING_OP_SEND`), `AF_PACKET` (`sendmmsg` / `send()` / `PACKET_MMAP`), Linux kernel `pktgen` (`pktgen.ko`), and standard UDP sockets (`sendmmsg`), including a nanosecond-per-packet kernel code-path breakdown and the `1.66 Mpps` `sk_buff` allocation ceiling observed on `netkit`.
2. **`veth` vs. `netkit` (`netkit-l2` / `netkit-l3` / `netkit-bpf`) & 5-Tuple `LRU_HASH` Counter Benchmarks across Single-Host (`n=5`), 100GbE (ConnectX-5), and 400GbE (ConnectX-7) ([netkit_summary.csv](../../../ja/benchmarks/netkit-and-veth-io/netkit_summary.csv)) (Section 2)**:
   - Direct comparison of `iperf3` (GSO/GRO ON vs. OFF) and `xdperf`, flow-count scaling under standard `ip_id: "flow"`, sender-side GRO control (`ip_id: "shared"`), short-lived TCP CPS (`/proc/net/softnet_stat` exact `13.00 → 10.00` calls/connection match), high-PPS UDP flood + TCP mixed workloads, and 5-tuple `LRU_HASH` (65,536 entries) overhead & 1-to-1 per-flow verification (`--tcp-flow-report`).
3. **Recommended Benchmark Topologies for Single-Host (`netns`), 2-Node 100G/400G Physical NICs, and Kubernetes + Cilium (`datapathMode=veth` and `datapathMode=netkit`) (Sections 3.1 to 3.3)**.
4. **Multi-Queue `veth` Scaling and Kubernetes Pod Considerations (Section 3.4)**:
   - UDP and TCP transmit rates as the `veth` queue count and the `xdperf` worker count grow from `1` to `32`, post-creation multi-queue expansion of CNI-created 1-queue `veth` pairs via `ethtool -L`, and behavior and mitigations for Pods under cgroup CPU limits (CFS quota and `cpuset.cpus`).

Reproducible scripts are available at:
- [docs/ja/scripts/bench_veth_io.sh](../../../ja/scripts/bench_veth_io.sh)
- [docs/ja/scripts/bench_netkit.sh](../../../ja/scripts/bench_netkit.sh)
- [docs/ja/scripts/bench_netkit_realnic.sh](../../../ja/scripts/bench_netkit_realnic.sh)

---

## 1. 8-Way Linux Packet Transmission Comparison on `veth` and `netkit` (1 Core, `n=5`)

### 1.1 Experimental Setup
- **Host**: Intel Xeon 6746E (64 vCPUs, single NUMA node), Linux `6.17.0-41-generic`
- **Topology**: Two network namespaces (`io-tx` ↔ `io-rx`) connected by a single-queue `veth` pair (`vtx` ↔ `vrx`). The receiving interface `vrx` runs `xdperf run --recv` (native XDP `XDP_DROP`) to eliminate receiver socket bottlenecks and isolate the single-core transmission ceiling (`taskset -c 2`).
- **Workload**: 64-byte L2 frames (14B Ethernet + 20B IPv4 + 8B UDP + 22B payload, excluding FCS), sweeping the UDP source port across **16,384 distinct values** (`10000`–`26383`) on every packet (`n=5` rounds, mean ± sample standard deviation SD).

### 1.2 `veth` 1-Core Benchmark Results ([veth_io_summary.csv](../../../ja/benchmarks/netkit-and-veth-io/veth_io_summary.csv))

| Rank | Transmission Mechanism | Kernel Internal Path on `veth` | TX PPS (Mean ± SD, `n=5`) | Time / Packet | 64B Bandwidth | `xdperf` Speedup |
|---:|---|---|---:|---:|---:|---:|
| **1** | **`xdperf`<br>(`BPF_F_TEST_XDP_LIVE_FRAMES` + In-Kernel XDP Diff)** | **In-kernel `page_pool` `xdp_frame` recycling with zero `sk_buff` allocations and zero userspace copies → `veth_xdp_xmit`** | **`9,557,197 ± 136,988 PPS`** | **`104.6 ns`** | **`4.893 Gbps`** | **Baseline (`1.00x`)** |
| **2** | **`AF_XDP`<br>(`XDP_COPY`, batch=64)** | `XDP_ZEROCOPY` fails with `errno=95 (EOPNOTSUPP)`.<br>Allocates `sk_buff` and copies from UMEM per packet (`xsk_generic_xmit`) | `1,776,021 ± 18,321 PPS` | `563.1 ns` | `0.909 Gbps` | **`xdperf` is 5.38x faster** |
| **3** | **`io_uring`<br>(`IORING_OP_SEND`, batch=64 + `QDISC_BYPASS`)** | 64 SQEs batched per `io_uring_enter`, per-packet `sk_buff` allocation + copy from userspace | `1,435,004 ± 37,477 PPS` | `696.9 ns` | `0.735 Gbps` | **`xdperf` is 6.66x faster** |
| **4** | **`AF_PACKET`<br>(`sendmmsg`, batch=64 + `QDISC_BYPASS`)** | 64 messages batched per syscall, per-packet `sk_buff` allocation + copy from userspace | `1,295,598 ± 28,444 PPS` | `771.8 ns` | `0.663 Gbps` | **`xdperf` is 7.38x faster** |
| **5** | **`AF_PACKET`<br>(`send()` + `PACKET_QDISC_BYPASS`)** | Per-packet syscall + `sk_buff` allocation + copy from userspace | `1,273,179 ± 3,529 PPS` | `785.4 ns` | `0.652 Gbps` | **`xdperf` is 7.51x faster** |
| **6** | **`AF_PACKET`<br>(`PACKET_MMAP` / `TPACKET_V2` `TX_RING` + `QDISC_BYPASS`)** | Shared mmap ring, per-packet `sk_buff` allocation + copy in `tpacket_snd()` | `1,251,056 ± 25,586 PPS` | `799.3 ns` | `0.641 Gbps` | **`xdperf` is 7.64x faster** |
| **7** | **Linux Kernel `pktgen`<br>(`pktgen.ko`, 16,384 port sweep, `clone_skb 0`)** | 100% in-kernel thread (`kpktgend`), but per-packet port modification requires `pktgen_alloc_skb()` + checksum + `veth_xmit` (SKB path) | `632,570 ± 3,900 PPS` | `1,580.9 ns` | `0.324 Gbps` | **`xdperf` is 15.11x faster** |
| **8** | **Standard UDP Socket<br>(`AF_INET` `SOCK_DGRAM` + `sendmmsg` batch=64)** | Full UDP/IP stack traversal + per-packet `sk_buff` allocation + copy | `425,993 ± 5,630 PPS` | `2,347.5 ns` | `0.218 Gbps` | **`xdperf` is 22.44x faster** |

### 1.3 Why `xdperf` Is 5.38x Faster Than `AF_XDP` on `veth` (Nanosecond Kernel Breakdown)

1. **`xdperf` (`104.6 ns / pkt` = `9.56 Mpps`)**:
   - In `net/bpf/test_run.c`, `bpf_test_run_xdp_live()` allocates `xdp_frame` buffers from an in-kernel `page_pool` and recycles them across millions of iterations inside a single `bpf_prog_test_run_opts` system call.
   - **Zero `struct sk_buff` allocations (`kmem_cache_alloc`), zero userspace memory copies, and zero per-batch system calls** occur during transmission.
   - On each frame, the XDP program (`xdp_tx`) overwrites 2 bytes of the UDP port and 2 bytes of the precomputed checksum diff in L1 cache (~15–20 ns), pushes batches of 64 `xdp_frame` pointers directly into the peer's `xdp_ring` via `veth_xdp_xmit()`, and the peer's `XDP_DROP` immediately returns pages to the `page_pool` ring (`__page_pool_put_page`).
2. **`AF_XDP` `XDP_COPY` (`563.1 ns / pkt` = `1.78 Mpps`, `+458.5 ns / pkt` penalty)**:
   - Because `veth` is a virtual software device without hardware DMA rings, binding an `AF_XDP` socket with `XDP_ZEROCOPY` fails with `errno=95 (EOPNOTSUPP)`, forcing fallback to `XDP_COPY` (`xsk_generic_xmit()` in `net/xdp/xsk.c`).
   - Despite the name `AF_XDP`, **`xsk_generic_xmit()` transmits via the legacy `sk_buff` path rather than `xdp_frame`**:
     1. Calls `sock_alloc_send_pskb()` on every packet to allocate and initialize a `struct sk_buff` and charge `sk_wmem_alloc` (~150 ns).
     2. Copies packet bytes from userspace UMEM to kernel `skb->data` (`skb_store_bits`) and sets `skb->destructor = xsk_destruct_skb` (~70 ns).
     3. Calls `dev_direct_xmit()` → `veth_xmit(skb)` (legacy SKB path, not `veth_xdp_xmit`), forcing the receiving peer (`veth_xdp_rcv_skb()`) to convert the `sk_buff` into an `xdp_buff` (~180 ns).
     4. Calls `kfree_skb()` → `xsk_destruct_skb()` to update the UMEM completion ring, plus a `sendto()` syscall every 64 packets (~60 ns).
   - Note that DPDK virtual PMDs (`--vdev=net_af_xdp` and `--vdev=net_af_packet`) and `Netmap` generic (emulated) mode on `veth` invoke the exact same `xsk_generic_xmit` or `tpacket_snd` / `alloc_skb` kernel paths and hit the same ceiling.

### 1.4 Direct Transmission on `netkit` (`nktx` ↔ `nkrx`) and the `1.66 Mpps` `sk_buff` Allocation Ceiling

Replacing the `veth` pair with a **`netkit` L2 pair (`ip link add nktx type netkit mode l2 peer nkrx`, dropping incoming UDP at `nkrx` TC ingress)** under the exact same 1-core workload yields:

| Transmission Mechanism | `veth` 1-Core PPS | `netkit` Direct TX 1-Core PPS | Behavior Change and Kernel Explanation |
|---|---:|---:|---|
| **`xdperf` (`BPF_F_TEST_XDP_LIVE_FRAMES`)** | **`9,557,197 PPS`** | **Not supported on `netkit`** (Rejected by Phase 0 guardrail) | `netkit` (`drivers/net/netkit.c`) does not implement `.ndo_bpf` or `.ndo_xdp_xmit` (`xdp_features = 0`), so live `xdp_frame` injection cannot run directly on a `netkit` device. Instead, `xdperf` must run on the sending `veth` / physical NIC / SR-IOV VF and redirect into `netkit` via `TCX ingress` (`bpf_redirect_peer`). |
| **`AF_XDP` (`XDP_COPY`, batch=64)** | `1,776,021 PPS` | **`1,658,604 PPS`** (`zc_errno=95`) | `XDP_ZEROCOPY` fails with `errno=95 (EOPNOTSUPP)`; `xsk_generic_xmit` (per-packet `alloc_skb` + UMEM copy) reached **`1.66 Mpps` (`602.9 ns/pkt`)**. |
| **Linux Kernel `pktgen` (`pktgen.ko`, 16,384 port sweep)** | `632,570 PPS` | **`1,658,527 PPS` (+162% faster)** | On `veth`, `veth_xmit(skb)` paid the cost of `veth_xdp_rcv_skb()` on the peer. On `netkit`, `netkit_xmit(skb)` processes the `sk_buff` inline without backlog/XDP conversion, speeding up by **2.62x** and **reaching nearly the same `1.66 Mpps` (`602.9 ns/pkt`) as `AF_XDP (XDP_COPY)`**. |
| **`io_uring` (`IORING_OP_SEND`, batch=64)** | `1,435,004 PPS` | **`1,274,201 PPS`** | Capped by per-packet `alloc_skb` + userspace copy (~1.27 Mpps). |
| **`AF_PACKET` (`sendmmsg`, batch=64)** | `1,295,598 PPS` | **`1,184,044 PPS`** | Same (~1.18 Mpps). |
| **`AF_PACKET` (`send()`)** | `1,273,179 PPS` | **`1,174,318 PPS`** | Same (~1.17 Mpps). |
| **`AF_PACKET` (`PACKET_MMAP` / `TPACKET_V2`)** | `1,251,056 PPS` | **`1,123,843 PPS`** | Same (~1.12 Mpps). |
| **Standard UDP Socket (`AF_INET` + `sendmmsg` batch=64)** | `425,993 PPS` | **`886,326 PPS` (+108% faster)** | Inline `netkit_xmit(skb)` doubles standard UDP socket throughput (**2.08x**), capped at 886k PPS by UDP/IP stack + `alloc_skb`. |

- **Key Takeaway**: When sending directly on the `netkit` pair, **userspace `AF_XDP (XDP_COPY)` (`1,658,604 PPS`) and in-kernel `pktgen` (`1,658,527 PPS`) reached nearly the same rate (`1.66 Mpps` = `603 ns/pkt`)**. The two take different paths, but both allocate and free a `struct sk_buff` per packet, which suggests that per-packet `sk_buff` allocation and freeing sets the transmit ceiling in this setup. This document calls that ceiling on `netkit` the `sk_buff` allocation ceiling.
  - `1.66 Mpps` is the rate measured on the `netkit` pair, not a device-independent limit: `AF_XDP (XDP_COPY)` on the `veth` pair reached `1.78 Mpps` (Section 1.2).
  - The peer also drops packets differently on the two pairs (native XDP `XDP_DROP` on `veth`, TC ingress on `netkit`), so the gap between the two pairs cannot be attributed to the device alone.
  - On both devices, the seven mechanisms that allocate an `sk_buff` per packet stayed below `1.8 Mpps/core` (mean of five runs on `veth`). Of the eight mechanisms measured, only `xdperf` (`BPF_F_TEST_XDP_LIVE_FRAMES`, `9.56 Mpps/core` on `veth`) avoids `sk_buff` allocation entirely.

---

## 2. `veth` vs. `netkit` and 5-Tuple `LRU_HASH` Counter Results (Single-Host, 100GbE, 400GbE)

Full data is recorded in [netkit_summary.csv](../../../ja/benchmarks/netkit-and-veth-io/netkit_summary.csv).

1. **Why `iperf3` Hides Datapath & Hook Overhead (`n=5` on 64 vCPU Single Host)**:
   - Default `iperf3 -P 4` (GSO/GRO ON) coalesces segments into 64 KiB super-skbs, reducing `/proc/net/softnet_stat` traversals per 1448B segment (`Softnet/seg`) to **`0.05–0.06`** and hiding the difference between `veth` (`144.36 ± 3.44 Gbps`) and `netkit-bpf` (`150.26 ± 2.87 Gbps`, **`+4.12% ± 2.89 pt`**).
   - Without touching receiver `ethtool` offloads, `xdperf` drives uncoalesced segment loads (`Softnet/seg = 2.51 → 2.00`), exposing a **`+16.71% ± 1.40 pt`** (`1w/16f`) to **`+19.90% ± 1.18 pt`** (`4w/64f`) advantage for `netkit-bpf`.
2. **Flow-Count Scaling under Standard `ip_id: "flow"` (`n=5`)**:
   - Even with standard per-flow sequential IP IDs (`ip_id: "flow"`), increasing concurrent flows from `1` (`+1.55% ± 0.65 pt`, `Softnet/seg = 0.65 → 0.54`, GRO active) to `16` → `64` → `128` → `256` naturally prevents GRO coalescing and exposes the peer-backlog bypass of `netkit-bpf`: **`+16.42% ± 0.62 pt` → `+16.85% ± 1.07 pt` → `+25.53% ± 0.45 pt` → `+31.99% ± 0.67 pt`** (`Softnet/seg = 2.98–3.00 → 2.00`).
3. **100GbE (ConnectX-5) and 400GbE (ConnectX-7) 2-Node Benchmarks** (each condition was run once, so run-to-run variance is not evaluated; see the `n_rounds` column of the CSV):
   - **Sustained TCP (`E3-A`)**: On 100GbE (`4w/64f`), `netkit-bpf` improves goodput by **`+25.4%` (`53.19 → 66.69 Gbps`, `ip_id: flow`)** and **`+32.3%` (`25.46 → 33.67 Gbps`, `ip_id: shared`)**; `ip_id: shared` also gives **`+24.5%`** at `1w/16f` and **`+35.2%`** at `8w/256f`. Where GRO still coalesces (`1w/16f`, `ip_id: flow`), the gain is only `+0.8%` (`19.01 → 19.17 Gbps`). On 400GbE (`4w/64f`), `netkit-bpf` reaches **`110.42 Gbps` (`+4.7%` from `105.42 Gbps`, `9.53M segs/s`, `0` retransmits)** under `ip_id: flow` and **`+10.4%` (`82.10 → 90.62 Gbps`)** under `ip_id: shared` (where the ~110 Gbps ceiling is governed by the single-process `xdperf-sink` socket reader sharing Core i9-12900K P/E cores with RX `ksoftirqd`).
   - **Short-Lived TCP CPS (`E3-B`)**: Across single-host (`n=5`), 100GbE, and 400GbE, receiver `Softnet/conn` drops from **`13.00–13.01`** on `veth` to **`10.00`** on `netkit-bpf` (eliminating all 3 return-path peer backlog traversals per connection), achieving **`27,050.4 CPS (+45.8%)`** on 400GbE (`4w/256s`); the same workload on 100GbE gained `+2.7%` (`23,780 → 24,418 CPS`).
   - **Noisy-Neighbor Mixed UDP Flood + TCP (`E3-C`, 100GbE 250k PPS)**: `netkit-bpf` cuts TCP retransmissions by **`54.9%` (`408 → 184`)** and TCP completion time by **`61.2%` (`8.901s → 3.451s`)**.
   - **5-Tuple `LRU_HASH` (65,536 entries) Overhead & Per-Flow Verification (`E3-D`)**: Counter overhead remains below 1% across `1w/16f` (`+0.41% ± 3.16 pt`), `4w/64f` (`+0.64% ± 3.59 pt`), `4w/256f` (`+0.35% ± 2.41 pt`), `4w/1,024f` (`+0.87% ± 0.90 pt`), high-CPS continuous insertion of **44,479 unique 5-tuples in 3s** (`-6.72% ± 12.67 pt`, 100% tuple match), and 400GbE at 110 Gbps (`-0.3%`, `110.25 → 109.87 Gbps`), with **100% (0 mismatch) 1-to-1 agreement** against `--tcp-flow-report` when uncoalesced (`window_segs=1`).

---

## 3. Recommended Benchmark Topologies (Single-Host, 100G/400G Hardware, and Kubernetes + Cilium)

Because `netkit` lacks `.ndo_xdp_xmit`, `xdperf` cannot transmit on it directly, and the seven `sk_buff`-based mechanisms measured in Section 1.4 reached at most `1.66 Mpps/core` there. Therefore, **always place the traffic generator (`xdperf`) on an `.ndo_xdp_xmit`-capable interface (`veth`, physical NIC, or SR-IOV VF), and swap only the DUT receiver Pod boundary between `veth` and `netkit` (Asymmetric Topology)**.

### 3.1 Pattern 1: Single-Host 3-Namespace Asymmetric Topology (`netns` / CI)

Used in [docs/ja/scripts/bench_netkit.sh](../../../ja/scripts/bench_netkit.sh) and [examples/tcp-netkit/](../../../../examples/tcp-netkit/README.md).

```
+-------------------+      +----------------------------------------+      +-----------------------+
|  Sender (b-tx)    |      |         DUT Host / Node (b-dut)        |      |  Receiver Pod (b-rx)  |
|  [Load Generator] |      |                                        |      |  [Target Workload]    |
|                   |      |  (1) Ingress Hook       (2) Pod Egress |      |                       |
|  xdperf           | veth |  vdut:                  edut:          |      |  erx:                 |
|  (LIVE_FRAMES +   |======|  - pass-through XDP     - veth OR      |======|  - xdperf-sink        |
|   In-Kernel TCP)  | vtx  |  - TCX ingress          - netkit       |      |    (or responder)     |
|                   |      |   (bpf_redirect_peer     (BPF_NETKIT_  |      |                       |
|  * Always veth    |      |    + fwd 5-tuple count)   PEER rev cnt)|      |  * Swap only this hop |
+-------------------+      +----------------------------------------+      +-----------------------+
        ^                                      ^
        |                                      |
  [Per-Flow CSV] ──────── 1-to-1 Verification ─┘
 (--tcp-flow-report)    (Forward: tx_pkts + rx_replies == TCX ingress)
                        (Reverse: rx_pkts              == BPF_NETKIT_PEER)
```

### 3.2 Pattern 2: 2-Node Physical 100GbE / 400GbE Topology

Used in [docs/ja/scripts/bench_netkit_realnic.sh](../../../ja/scripts/bench_netkit_realnic.sh).

```
+----------------------------+            +----------------------------------------------------+
| Sender Node (Node 1)       |            | Receiver DUT Node (Node 2)                         |
|                            |            |                                                    |
|  xdperf (Native XDP)       | 100G/400G  | Physical NIC (mlx5, etc.)   Receiver Pod (b-rx)    |
|  - ip_id: "flow" (GRO ON)  |============| - TCX ingress          edut  erx:                  |
|  - ip_id: "shared"(No GRO) |  Physical  |  (bpf_redirect_peer   ====== - xdperf-sink         |
|  - --tcp-flow-report       |    Link    |   + fwd 5-tuple count)  ^    (or --tcp-server)     |
+----------------------------+            |                         |                          |
                                          |                BPF_NETKIT_PEER                     |
                                          |               (bpf_redirect_neigh + rev count)     |
                                          +----------------------------------------------------+
```

### 3.3 Pattern 3: Kubernetes + Cilium Topologies and Required Settings

When benchmarking Cilium on Kubernetes, choose the topology based on Cilium's `bpf.datapathMode` (**`veth`** vs. **`netkit`**):

#### (A) Cilium with `bpf.datapathMode=veth` (Default)
Deploy both the client (`xdperf`) and server (`xdperf-sink`) as standard Kubernetes Pods on separate worker nodes.

```
[Worker Node 1 (Sender)]                          [Worker Node 2 (Receiver)]
+-----------------------------------+           +-----------------------------------+
| Client Pod (privileged: true)     |           | Server Pod                        |
|  xdperf (--xdp-mode generic)      |           |  xdperf-sink (or --tcp-server)    |
|         |                         |           |         ^                         |
|       eth0 (veth)                 |           |       eth0 (veth)                 |
+---------||------------------------+           +---------||------------------------+
          || veth pair                                    || veth pair
+---------||------------------------+           +---------||------------------------+
|       lxcXXX (* GRO on required!) |           |       lxcYYY                      |
|         v                         |           |         ^  |                      |
|  [cil_from_container] (fwd count) |           |         |  v [cil_from_container] |
|         |                         |           |  [cil_to_container]  (rev count)  |
|         v (Native Routing/VXLAN)  |           |         ^                         |
|   Physical NIC / eth0 ============|===========|===> Physical NIC / eth0           |
+-----------------------------------+           +-----------------------------------+
```

- **Three Essential Settings for Cilium `veth` Mode**:
  1. **Enable GRO on the sender Pod's host-side `lxcXXX` interface (`ethtool -K lxcXXX gro on`)**: Cilium disables GRO on host `lxc*` interfaces by default. In the Linux kernel `veth` driver, `veth_xdp_xmit()` drops live frames when the peer interface has neither an XDP program attached nor GRO enabled (`rq->napi == NULL`). Enabling GRO on the sender's host-side `lxcXXX` activates NAPI and allows live frames to flow into `cil_from_container`.
  2. **Run `xdperf` inside the client Pod with `--xdp-mode generic`**: Because Cilium attaches TCX (`cil_from_container`) rather than XDP to `lxc*`, native XDP on the Pod `eth0` cannot wake the peer NAPI via `veth_xdp_flush()`. `--xdp-mode generic` transmits via `dev_queue_xmit()` directly into `cil_from_container`.
  3. **Use direct Pod IP or set `socketLB.hostNamespaceOnly=true` for `ClusterIP` Services**: Cilium's default Socket-LB hooks `connect()` syscalls, which raw XDP frames bypass. Target the receiver **Pod IP** directly, or set `socketLB.hostNamespaceOnly=true` so Cilium performs per-packet Service translation inside `cil_from_container`.

#### (B) Cilium with `bpf.datapathMode=netkit` (or `netkit-l2`)
Because Cilium-managed Pod `eth0` interfaces are `netkit` devices (no `.ndo_xdp_xmit`), keep the receiver as a standard Cilium `netkit` Pod and use either **Topology 2A** or **Topology 2B** for the sender:

- **Topology 2A (Maximum Throughput / 100G–400G Physical NIC or SR-IOV VF Sender)**:
  - Run the sender `xdperf` Pod on Worker Node 1 with **`hostNetwork: true`** (using the node's physical NIC or `kind` node `eth0` with `--xdp-mode native`) or with a **Cilium DRA / Multus SR-IOV VF**.
  - Run the receiver `xdperf-sink` Pod on Worker Node 2 as a standard **Cilium `netkit` Pod**. Traffic traverses Worker Node 2's `cil_from_netdev` (`bpf_redirect_peer`) into the `netkit` Pod and returns through `BPF_NETKIT_PEER` (`cil_from_container`).
- **Topology 2B (Full Pod-to-Pod East-West Traversing `cil_from_container` on Both Ends)**:
  - Use a `CiliumNodeConfig` resource to run **Worker Node 1 (Sender) in `datapath-mode: veth`** and **Worker Node 2 (Receiver DUT) in `datapath-mode: netkit`**:
    ```yaml
    apiVersion: cilium.io/v2
    kind: CiliumNodeConfig
    metadata:
      name: netkit-dut-node
      namespace: kube-system
    spec:
      nodeSelector:
        matchLabels:
          kubernetes.io/hostname: worker-node-2
      defaults:
        datapath-mode: netkit
    ```
  - This allows the sender Pod on Worker Node 1 to inject traffic from a standard `veth` Pod through `cil_from_container`, while the receiver Pod on Worker Node 2 is tested as a native Cilium `netkit` Pod.

#### (C) Quick Reference Matrix for Kubernetes + Cilium

| Benchmark Goal | Sender Pod (`xdperf`) Placement | Receiver Pod (`xdperf-sink`) Placement | Key Configuration |
|---|---|---|---|
| **1. Standard Cilium (`veth`) Pod-to-Pod & Datapath Plugins** | Standard Pod (`veth`) on Worker 1<br>`--xdp-mode generic` | Standard Pod (`veth`) on Worker 2 | `ethtool -K lxcXXX gro on` on Worker 1 (`socketLB.hostNamespaceOnly=true` if testing `ClusterIP`) |
| **2. Cilium `netkit` Mode Maximum Throughput (100G/400G)** | **`hostNetwork: true` Pod** (or **DRA / SR-IOV VF Pod**) on Worker 1<br>`--xdp-mode native` | Standard Pod (**`netkit`**) on Worker 2 | Drive line-rate traffic from Worker 1's physical NIC/VF into Worker 2's `netkit` Pod |
| **3. Cilium `netkit` Mode Traversing Pod `cil_from_container` on Both Ends** | Standard Pod on Worker 1 (**`veth` node**)<br>`--xdp-mode generic` | Standard Pod on Worker 2 (**`netkit` node**) | Use `CiliumNodeConfig` to set Worker 2 to `netkit` and keep Worker 1 on `veth` (`lxcXXX gro on`) |

---

### 3.4 Multi-Queue `veth` Scaling (301.5 Mpps UDP / 225.7 Gbps TCP) and Kubernetes Pod Verification (Dynamic `ethtool -L` & cgroup CPU Limits)

#### (1) Multi-Queue `veth` Linear Scaling Ceiling (64 vCPU Xeon 6746E, Linux `6.17.0-41-generic`)

Scaling `veth` queues (`numtxqueues N numrxqueues N`) and `xdperf` workers (`--parallelism N`) from `1` to `32` on a single-host `veth` pair achieves linear scaling up to **301.50 Mpps** (64B UDP) and **225.69 Gbps** (stateful 1448B-MSS TCP with 0 retransmissions):

| `veth` Queues / Workers | 64B UDP (16,384 Port Sweep, Peer `--recv`) | Stateful Bidirectional TCP (MSS 1448, Peer `--tcp-server` XDP Responder) | TCP Retransmits (`RTX`) |
|---:|---:|---:|---:|
| **1 queue / 1 worker** | `8.43 Mpps` (`4.32 Gbps`) | `5.19 Gbps` (`0.45 M segs/s`, 16 flows) | **0** |
| **4 queues / 4 workers** | `37.18 Mpps` (`19.04 Gbps`) | `31.10 Gbps` (`2.69 M segs/s`, 64 flows) | **0** |
| **8 queues / 8 workers** | `79.59 Mpps` (`40.75 Gbps`) | `61.09 Gbps` (`5.27 M segs/s`, 128 flows) | **0** |
| **16 queues / 16 workers** | `153.43 Mpps` (`78.56 Gbps`) | `111.90 Gbps` (`9.66 M segs/s`, 256 flows) | **0** |
| **24 queues / 24 workers** | — | `169.73 Gbps` (`14.65 M segs/s`, 384 flows) | **0** |
| **32 queues / 32 workers** | **`301.50 Mpps` (`154.37 Gbps` at 64B)** | **`225.69 Gbps` (`19.48 M segs/s`, 512 flows)** | **0** |

#### (2) Dynamic Post-Creation Multi-Queue Expansion on CNI-Created 1-Queue `veth` Pairs via `ethtool -L`

Kubernetes CNIs (such as Cilium and Calico) initialize Pod `veth` pairs (Pod `eth0` ↔ host `lxcXXX`) with `1` active TX/RX queue (`real_num_tx_queues = 1`). However, because Linux's `veth_newlink()` (`drivers/net/veth.c`) allocates `num_possible_cpus()` queue structures up front at device creation time, **you can dynamically expand an already-running Pod's `veth` pair to 16 or 32 queues on the fly using `ethtool -L` on both ends without recreating the Pod or modifying the CNI**:

```bash
# 1. Expand Pod eth0 to 16 TX/RX queues dynamically
kubectl exec -it <pod-name> -- ethtool -L eth0 rx 16 tx 16

# 2. Identify the host-side peer lxcXXX and expand it to 16 TX/RX queues (+ enable GRO for Cilium veth mode)
IFINDEX=$(kubectl exec <pod-name> -- cat /sys/class/net/eth0/iflink)
HOST_LXC=$(ip -o link | awk -F': ' -v idx="$IFINDEX" '$1 == idx {split($2, a, "@"); print a[1]}')
sudo ethtool -L "$HOST_LXC" rx 16 tx 16
sudo ethtool -K "$HOST_LXC" gro on
```

Empirical verification on a default 1-queue `veth` pair (`ip link add vtx type veth peer name vrx`) driving 16 workers / 256 TCP flows for 3s:

| Configuration (Same Default-Created `veth` Pair) | Goodput (Gbps) | Data Segs/s | `xdp_xmit_errors` (Ring Overflow Drops) | TCP Retransmits (`RTX`) | `warnVethQueues` Triggered |
|---|---:|---:|---:|---:|---|
| **1A: Default CNI 1-Queue State (`16w / 256f`)** | `8.79 Gbps` | `0.76 M segs/s` | `10,375` | `25,584` | `True` |
| **1B: Post-Creation Dynamic `ethtool -L <dev> rx 16 tx 16` on Both Ends** | **`112.61 Gbps (+12.8x)`** | **`9.72 M segs/s`** | **`0`** | **`0`** | `False` |

#### (3) Empirical Verification of cgroup vCPU Limits (`cpu.max` CFS Quota and `cpuset.cpus` Pinning)

When a Kubernetes Pod runs under cgroup vCPU restrictions, three critical interactions occur between the kernel scheduler, `veth_xdp_xmit()`, and `xdperf`:

##### Verification A: CFS Quota Throttling Collapse When `--parallelism` Exceeds `limits.cpu` (`CPUQuota=200%` = 2 vCPUs)
Because each `xdperf` TX worker consumes 100% of one core, setting `--parallelism` higher than the Pod's CFS quota (`limits.cpu`) exhausts the 100ms period quota early and freezes all worker threads for the remainder of every 100ms window, stalling TCP ACK processing and collapsing throughput:

| cgroup v2 CFS Quota | `--parallelism` (Workers) | Goodput (Gbps) | Data Segs/s | `window_stalls` | Observed Behavior |
|---|---:|---:|---:|---:|---|
| `CPUQuota=200%` (`limits.cpu: "2"`) | **`2` (Matches Quota)** | **`24.04 Gbps`** | **`2.08 M segs/s`** | `9,791,318` | Continuous unthrottled transmission |
| `CPUQuota=200%` (`limits.cpu: "2"`) | `8` (4x Quota) | `2.78 Gbps (-88.4%)` | `0.24 M segs/s` | `17,287,522` | Frozen 75ms per 100ms period (~8.6x collapse) |
| `CPUQuota=200%` (`limits.cpu: "2"`) | `16` (8x Quota) | `1.49 Gbps (-93.8%)` | `0.13 M segs/s` | `21,577,179` | Frozen 87.5ms per 100ms period (~16.1x collapse) |

* **Rule**: Under CFS quota (`limits.cpu: N`), always set **`--parallelism <= N`**.

##### Verification B: Two Pitfalls Under `cpuset.cpus` Pinning (Kubernetes CPU Manager `static` Policy, e.g., `AllowedCPUs=2,6,10,14`)
1. **`SchedSetaffinity` (`EINVAL`) with Default `--cpu-mode auto`**:
   - Because `DetectTopology()` reads host-wide `/sys/devices/system/node/node*/cpulist` (`CPU 0..63`), running `--cpu-mode auto --parallelism 4` inside a cgroup restricted to `AllowedCPUs=2,6,10,14` attempts to pin worker 0 to `CPU 0` and fails immediately with:
     ```text
     xdperf client start failed: worker failed: failed to set CPU affinity: invalid argument
     ```
   - **Rule**: Inside a `cpuset`-restricted Pod, pass the Pod's `/sys/fs/cgroup/cpuset.cpus.effective` list explicitly via `--cpu-mode 2,6,10,14`.
2. **`veth_xdp_xmit()` Modulo Queue Collision (`cpu % peer_rx_queues`) on Non-Contiguous CPUs**:
   - In the Linux kernel, `veth_xdp_xmit()` selects the peer's RX `xdp_ring` using **`smp_processor_id() % rcv->real_num_rx_queues`**.
   - When a Pod is assigned 4 non-contiguous CPUs **`2, 6, 10, 14`** and the peer `veth` is configured with `4` queues (`ethtool -L vrx rx 4 tx 4`), all 4 CPUs hash to the exact same queue (`2%4 = 6%4 = 10%4 = 14%4 = 2`), funneling 100% of traffic from all 4 workers into `rx_queue_2` (256-frame ring) and causing severe drops and retransmissions.
   - Raising the peer queue count to **`ethtool -L vrx rx 16 tx 16` ($\ge \max(c_i) + 1$)** maps `cpu % 16` to 4 distinct queues (`rx_queue_2`, `rx_queue_6`, `rx_queue_10`, `rx_queue_14`), eliminating all drops and restoring full 4-core throughput (**`8.27 → 32.41 Gbps`, +3.92x**):

| `AllowedCPUs=2,6,10,14` (`--cpu-mode 2,6,10,14`, 4w/64f) | Peer `ethtool -L` Queues | Goodput (Gbps) | `xdp_xmit_errors` | TCP Retransmits (`RTX`) | Measured Peer `ethtool -S vrx` Per-Queue Packet Distribution |
|---|---:|---:|---:|---:|---|
| **3B: 4 Queues (`cpu % 4 == 2` Modulo Collision)** | `rx 4 tx 4` | `8.27 Gbps` | `1,936` | `6,713` | **`rx_queue_2: 2,146,911`** (`rx_queue_0: 3`, `rx_queue_1: 2`, `rx_queue_3: 0`) |
| **3C: 16 Queues (`cpu % 16 = 2,6,10,14` Collision-Free)** | **`rx 16 tx 16`** | **`32.41 Gbps (+3.92x)`** | **`0`** | **`0`** | **`rx_queue_2: 2,125,632` / `rx_queue_6: 2,079,424` / `rx_queue_10: 2,107,328` / `rx_queue_14: 2,082,898`** |

* **Rule**: When pinned to non-contiguous CPU IDs $c_1, \dots, c_W$, set `ethtool -L` queue count $Q$ so that all $c_i \bmod Q$ are distinct (most reliably **$Q \ge \max(c_i) + 1$**).

