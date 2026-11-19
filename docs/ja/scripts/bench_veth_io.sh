#!/bin/bash
# docs/ja/scripts/bench_veth_io.sh
# Reproducible benchmark comparing 8 Linux packet transmission mechanisms on a 1-core veth pair:
#   1. xdperf (BPF_F_TEST_XDP_LIVE_FRAMES + in-kernel XDP Diff)
#   2. AF_XDP (XDP_COPY, batch=64; also probes XDP_ZEROCOPY errno on veth)
#   3. io_uring (IORING_OP_SEND, batch=64 + PACKET_QDISC_BYPASS)
#   4. AF_PACKET (sendmmsg, batch=64 + PACKET_QDISC_BYPASS)
#   5. AF_PACKET (send() per packet + PACKET_QDISC_BYPASS)
#   6. AF_PACKET (PACKET_MMAP / TPACKET_V2 TX_RING + PACKET_QDISC_BYPASS)
#   7. Linux kernel pktgen (pktgen.ko, 16,384 UDP port sweep, clone_skb=0)
#   8. Standard UDP socket (AF_INET SOCK_DGRAM + sendmmsg, batch=64)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
XDPERF_BIN="${XDPERF_BIN:-${REPO_ROOT}/out/bin/xdperf}"
PLUGIN_PATH="${PLUGIN_PATH:-${REPO_ROOT}/out/bin}"
ROUNDS="${ROUNDS:-5}"
DURATION_S="${DURATION_S:-2}"
PIN_CPU="${PIN_CPU:-2}"
XDPERF_PKT_COUNT="${XDPERF_PKT_COUNT:-14000000}"
PKTGEN_PKT_COUNT="${PKTGEN_PKT_COUNT:-5000000}"

if [[ $EUID -ne 0 ]]; then
    echo "Error: must be run as root (sudo)" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d /run/xdperf-veth-iobench.XXXXXX)"
RX_PID=""

cleanup_netns() {
    if [ -n "${RX_PID}" ]; then
        kill -INT "${RX_PID}" 2>/dev/null || true
        wait "${RX_PID}" 2>/dev/null || true
        RX_PID=""
    fi
    ip netns del io-tx 2>/dev/null || true
    ip netns del io-rx 2>/dev/null || true
}

cleanup_all() {
    cleanup_netns
    rm -rf "${WORK_DIR}"
}
trap cleanup_all EXIT

cat > "${WORK_DIR}/veth_io_bench.c" << 'EOF'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <linux/io_uring.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define BATCH_SIZE 64
#define PKT_LEN 64

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void fill_dummy_pkt(uint8_t *buf, uint16_t seq) {
    memset(buf, 0, PKT_LEN);
    buf[0] = 0x02; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x02;
    buf[6] = 0x02; buf[7] = 0x00; buf[8] = 0x00; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x01;
    buf[12] = 0x08; buf[13] = 0x00;
    buf[14] = 0x45;
    buf[16] = 0x00; buf[17] = PKT_LEN - 14;
    buf[22] = 64; buf[23] = 17;
    buf[26] = 10; buf[27] = 200; buf[28] = 1; buf[29] = 1;
    buf[30] = 10; buf[31] = 200; buf[32] = 1; buf[33] = 2;
    uint16_t sport = htons(10000 + (seq & 0x3fff));
    uint16_t dport = htons(5201);
    uint16_t ulen = htons(PKT_LEN - 14 - 20);
    memcpy(buf + 34, &sport, 2);
    memcpy(buf + 36, &dport, 2);
    memcpy(buf + 38, &ulen, 2);
}

static int run_af_xdp_tx(int ifindex, int duration_s) {
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd < 0) { perror("socket(AF_XDP)"); return 1; }

    size_t umem_size = (size_t)NUM_FRAMES * FRAME_SIZE;
    void *umem = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (umem == MAP_FAILED) { perror("mmap umem"); return 1; }

    for (int i = 0; i < NUM_FRAMES; i++) {
        fill_dummy_pkt((uint8_t *)umem + i * FRAME_SIZE, (uint16_t)i);
    }

    struct xdp_umem_reg mr = {
        .addr = (uint64_t)(uintptr_t)umem,
        .len = umem_size,
        .chunk_size = FRAME_SIZE,
        .headroom = 0,
    };
    if (setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        perror("XDP_UMEM_REG"); return 1;
    }
    int ring_size = NUM_FRAMES;
    if (setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size, sizeof(ring_size)) < 0 ||
        setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size, sizeof(ring_size)) < 0 ||
        setsockopt(fd, SOL_XDP, XDP_TX_RING, &ring_size, sizeof(ring_size)) < 0) {
        perror("setsockopt rings"); return 1;
    }

    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    if (getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        perror("XDP_MMAP_OFFSETS"); return 1;
    }

    void *cr_map = mmap(NULL, off.cr.desc + NUM_FRAMES * sizeof(uint64_t),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    void *tx_map = mmap(NULL, off.tx.desc + NUM_FRAMES * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_TX_RING);
    if (cr_map == MAP_FAILED || tx_map == MAP_FAILED) { perror("mmap rings"); return 1; }

    int zc_errno = 0;
    {
        int fd_zc = socket(AF_XDP, SOCK_RAW, 0);
        if (fd_zc >= 0) {
            void *u2 = mmap(NULL, 64 * FRAME_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            struct xdp_umem_reg mr2 = { .addr = (uint64_t)(uintptr_t)u2, .len = 64 * FRAME_SIZE, .chunk_size = FRAME_SIZE };
            setsockopt(fd_zc, SOL_XDP, XDP_UMEM_REG, &mr2, sizeof(mr2));
            int rs2 = 64;
            setsockopt(fd_zc, SOL_XDP, XDP_UMEM_FILL_RING, &rs2, sizeof(rs2));
            setsockopt(fd_zc, SOL_XDP, XDP_UMEM_COMPLETION_RING, &rs2, sizeof(rs2));
            setsockopt(fd_zc, SOL_XDP, XDP_TX_RING, &rs2, sizeof(rs2));
            struct sockaddr_xdp sxdp_zc = {
                .sxdp_family = PF_XDP,
                .sxdp_ifindex = ifindex,
                .sxdp_queue_id = 0,
                .sxdp_flags = XDP_ZEROCOPY,
            };
            if (bind(fd_zc, (struct sockaddr *)&sxdp_zc, sizeof(sxdp_zc)) < 0) {
                zc_errno = errno;
            }
            munmap(u2, 64 * FRAME_SIZE);
            close(fd_zc);
        }
    }

    struct sockaddr_xdp sxdp = {
        .sxdp_family = PF_XDP,
        .sxdp_ifindex = ifindex,
        .sxdp_queue_id = 0,
        .sxdp_flags = XDP_COPY,
    };
    if (bind(fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        perror("bind(AF_XDP, XDP_COPY)"); return 1;
    }

    volatile uint32_t *cr_prod = (uint32_t *)((uint8_t *)cr_map + off.cr.producer);
    volatile uint32_t *cr_cons = (uint32_t *)((uint8_t *)cr_map + off.cr.consumer);
    volatile uint32_t *tx_prod = (uint32_t *)((uint8_t *)tx_map + off.tx.producer);
    volatile uint32_t *tx_cons = (uint32_t *)((uint8_t *)tx_map + off.tx.consumer);
    struct xdp_desc *tx_descs = (struct xdp_desc *)((uint8_t *)tx_map + off.tx.desc);

    uint32_t mask = NUM_FRAMES - 1;
    uint64_t syscalls = 0;
    uint32_t cur_frame = 0;

    signal(SIGALRM, sig_handler);
    alarm(duration_s);
    double t0 = now_sec();

    while (running) {
        uint32_t c_prod = __atomic_load_n(cr_prod, __ATOMIC_ACQUIRE);
        uint32_t c_cons = *cr_cons;
        if (c_prod != c_cons) {
            __atomic_store_n(cr_cons, c_prod, __ATOMIC_RELEASE);
        }

        uint32_t t_prod = *tx_prod;
        uint32_t t_cons = __atomic_load_n(tx_cons, __ATOMIC_ACQUIRE);
        uint32_t free_slots = NUM_FRAMES - (t_prod - t_cons);
        if (free_slots < BATCH_SIZE) {
            sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
            syscalls++;
            continue;
        }
        for (int i = 0; i < BATCH_SIZE; i++) {
            uint32_t idx = (t_prod + i) & mask;
            uint8_t *pkt = (uint8_t *)umem + (cur_frame & mask) * FRAME_SIZE;
            uint16_t sport = htons(10000 + (cur_frame & 0x3fff));
            memcpy(pkt + 34, &sport, 2);
            tx_descs[idx].addr = (uint64_t)(cur_frame & mask) * FRAME_SIZE;
            tx_descs[idx].len = PKT_LEN;
            tx_descs[idx].options = 0;
            cur_frame++;
        }
        __atomic_store_n(tx_prod, t_prod + BATCH_SIZE, __ATOMIC_RELEASE);
        sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        syscalls++;
    }
    double elapsed = now_sec() - t0;
    uint32_t actual_consumed = __atomic_load_n(tx_cons, __ATOMIC_ACQUIRE);
    printf("{\"mode\":\"af_xdp_copy\",\"zc_errno\":%d,\"pkts\":%u,\"sec\":%.4f,\"pps\":%.1f,\"syscalls\":%lu}\n",
           zc_errno, actual_consumed, elapsed, actual_consumed / elapsed, syscalls);
    close(fd);
    return 0;
}

static int run_af_packet_mmap(int ifindex, int duration_s) {
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { perror("socket(AF_PACKET)"); return 1; }
    int ver = TPACKET_V2, loss = 1, qdisc_bypass = 1;
    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
    setsockopt(fd, SOL_PACKET, PACKET_LOSS, &loss, sizeof(loss));
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));

    struct tpacket_req req = {
        .tp_block_size = 4096,
        .tp_frame_size = 2048,
        .tp_block_nr = NUM_FRAMES / 2,
        .tp_frame_nr = NUM_FRAMES,
    };
    if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
        perror("PACKET_TX_RING"); return 1;
    }
    size_t ring_len = (size_t)req.tp_block_size * req.tp_block_nr;
    uint8_t *ring = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (ring == MAP_FAILED) { perror("mmap packet_tx_ring"); return 1; }

    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = ifindex, .sll_protocol = htons(ETH_P_IP) };
    bind(fd, (struct sockaddr *)&sll, sizeof(sll));

    uint32_t hdr_off = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
    for (uint32_t i = 0; i < NUM_FRAMES; i++) {
        fill_dummy_pkt(ring + i * req.tp_frame_size + hdr_off, (uint16_t)i);
    }

    uint32_t idx = 0, mask = NUM_FRAMES - 1;
    uint64_t total_sent = 0, syscalls = 0;
    signal(SIGALRM, sig_handler);
    alarm(duration_s);
    double t0 = now_sec();
    while (running) {
        int queued = 0;
        for (int i = 0; i < BATCH_SIZE; i++) {
            struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)(ring + ((idx + i) & mask) * req.tp_frame_size);
            if (hdr->tp_status != TP_STATUS_AVAILABLE) break;
            uint8_t *pkt = (uint8_t *)hdr + hdr_off;
            uint16_t sport = htons(10000 + ((idx + i) & 0x3fff));
            memcpy(pkt + 34, &sport, 2);
            hdr->tp_len = PKT_LEN;
            __atomic_store_n(&hdr->tp_status, TP_STATUS_SEND_REQUEST, __ATOMIC_RELEASE);
            queued++;
        }
        if (queued > 0) {
            idx += queued;
            int ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
            syscalls++;
            if (ret > 0) total_sent += ret / PKT_LEN;
        } else {
            sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
            syscalls++;
        }
    }
    double elapsed = now_sec() - t0;
    printf("{\"mode\":\"af_packet_mmap\",\"pkts\":%lu,\"sec\":%.4f,\"pps\":%.1f,\"syscalls\":%lu}\n",
           total_sent, elapsed, total_sent / elapsed, syscalls);
    close(fd);
    return 0;
}

static int run_raw_sendto(int ifindex, int duration_s) {
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int qdisc_bypass = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));
    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = ifindex, .sll_protocol = htons(ETH_P_IP) };
    bind(fd, (struct sockaddr *)&sll, sizeof(sll));
    uint8_t pkt[PKT_LEN];
    fill_dummy_pkt(pkt, 0);
    uint64_t total_sent = 0;
    signal(SIGALRM, sig_handler);
    alarm(duration_s);
    double t0 = now_sec();
    while (running) {
        uint16_t sport = htons(10000 + (total_sent & 0x3fff));
        memcpy(pkt + 34, &sport, 2);
        if (send(fd, pkt, PKT_LEN, 0) == PKT_LEN) total_sent++;
    }
    double elapsed = now_sec() - t0;
    printf("{\"mode\":\"af_packet_sendto\",\"pkts\":%lu,\"sec\":%.4f,\"pps\":%.1f,\"syscalls\":%lu}\n",
           total_sent, elapsed, total_sent / elapsed, total_sent);
    close(fd);
    return 0;
}

static int run_af_packet_sendmmsg(int ifindex, int duration_s) {
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int qdisc_bypass = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));
    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = ifindex, .sll_protocol = htons(ETH_P_IP) };
    bind(fd, (struct sockaddr *)&sll, sizeof(sll));

    uint8_t pkts[BATCH_SIZE][PKT_LEN];
    struct iovec iov[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH_SIZE; i++) {
        fill_dummy_pkt(pkts[i], (uint16_t)i);
        iov[i].iov_base = pkts[i];
        iov[i].iov_len = PKT_LEN;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    uint64_t total_sent = 0, syscalls = 0;
    uint32_t seq = 0;
    signal(SIGALRM, sig_handler);
    alarm(duration_s);
    double t0 = now_sec();
    while (running) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            uint16_t sport = htons(10000 + (seq++ & 0x3fff));
            memcpy(pkts[i] + 34, &sport, 2);
        }
        int ret = sendmmsg(fd, msgs, BATCH_SIZE, 0);
        syscalls++;
        if (ret > 0) total_sent += ret;
    }
    double elapsed = now_sec() - t0;
    printf("{\"mode\":\"af_packet_sendmmsg\",\"pkts\":%lu,\"sec\":%.4f,\"pps\":%.1f,\"syscalls\":%lu}\n",
           total_sent, elapsed, total_sent / elapsed, syscalls);
    close(fd);
    return 0;
}

static int run_udp_sendmmsg(int duration_s) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(5201) };
    inet_pton(AF_INET, "10.200.1.2", &dst.sin_addr);
    connect(fd, (struct sockaddr *)&dst, sizeof(dst));

    uint8_t payload[BATCH_SIZE][22];
    struct iovec iov[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];
    memset(msgs, 0, sizeof(msgs));
    memset(payload, 'A', sizeof(payload));
    for (int i = 0; i < BATCH_SIZE; i++) {
        iov[i].iov_base = payload[i];
        iov[i].iov_len = 22;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    uint64_t total_sent = 0, syscalls = 0;
    signal(SIGALRM, sig_handler);
    alarm(duration_s);
    double t0 = now_sec();
    while (running) {
        int ret = sendmmsg(fd, msgs, BATCH_SIZE, 0);
        syscalls++;
        if (ret > 0) total_sent += ret;
    }
    double elapsed = now_sec() - t0;
    printf("{\"mode\":\"udp_socket_sendmmsg\",\"pkts\":%lu,\"sec\":%.4f,\"pps\":%.1f,\"syscalls\":%lu}\n",
           total_sent, elapsed, total_sent / elapsed, syscalls);
    close(fd);
    return 0;
}

static int sys_io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}
static int sys_io_uring_enter(int ring_fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
    return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete, flags, NULL, 0);
}

static int run_io_uring_send(int ifindex, int duration_s) {
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int qdisc_bypass = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));
    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_ifindex = ifindex, .sll_protocol = htons(ETH_P_IP) };
    bind(fd, (struct sockaddr *)&sll, sizeof(sll));

    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    int ring_fd = sys_io_uring_setup(128, &p);
    if (ring_fd < 0) { perror("io_uring_setup"); return 1; }

    size_t sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    uint8_t *sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
    uint8_t *cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
                                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);

    volatile unsigned *sq_tail = (unsigned *)(sq_ptr + p.sq_off.tail);
    volatile unsigned *sq_mask = (unsigned *)(sq_ptr + p.sq_off.ring_mask);
    unsigned *sq_array = (unsigned *)(sq_ptr + p.sq_off.array);
    volatile unsigned *cq_head = (unsigned *)(cq_ptr + p.cq_off.head);
    volatile unsigned *cq_tail = (unsigned *)(cq_ptr + p.cq_off.tail);
    volatile unsigned *cq_mask = (unsigned *)(cq_ptr + p.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(cq_ptr + p.cq_off.cqes);

    uint8_t pkts[BATCH_SIZE][PKT_LEN];
    for (int i = 0; i < BATCH_SIZE; i++) fill_dummy_pkt(pkts[i], (uint16_t)i);

    uint64_t total_sent = 0, syscalls = 0;
    uint32_t seq = 0;
    signal(SIGALRM, sig_handler);
    alarm(duration_s);
    double t0 = now_sec();
    while (running) {
        unsigned tail = *sq_tail;
        for (int i = 0; i < BATCH_SIZE; i++) {
            unsigned idx = (tail + i) & *sq_mask;
            uint16_t sport = htons(10000 + (seq++ & 0x3fff));
            memcpy(pkts[i] + 34, &sport, 2);
            memset(&sqes[idx], 0, sizeof(struct io_uring_sqe));
            sqes[idx].opcode = IORING_OP_SEND;
            sqes[idx].fd = fd;
            sqes[idx].addr = (uint64_t)(uintptr_t)pkts[i];
            sqes[idx].len = PKT_LEN;
            sq_array[idx] = idx;
        }
        __atomic_store_n(sq_tail, tail + BATCH_SIZE, __ATOMIC_RELEASE);
        int ret = sys_io_uring_enter(ring_fd, BATCH_SIZE, BATCH_SIZE, IORING_ENTER_GETEVENTS);
        syscalls++;
        if (ret < 0 && errno == EINTR) break;
        unsigned head = *cq_head;
        unsigned ctail = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
        while (head != ctail) {
            if (cqes[head & *cq_mask].res == PKT_LEN) total_sent++;
            head++;
        }
        __atomic_store_n(cq_head, head, __ATOMIC_RELEASE);
    }
    double elapsed = now_sec() - t0;
    printf("{\"mode\":\"io_uring_send\",\"pkts\":%lu,\"sec\":%.4f,\"pps\":%.1f,\"syscalls\":%lu}\n",
           total_sent, elapsed, total_sent / elapsed, syscalls);
    close(ring_fd);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) return 1;
    int ifindex = if_nametoindex(argv[2]);
    int dur = atoi(argv[3]);
    if (strcmp(argv[1], "af_xdp") == 0) return run_af_xdp_tx(ifindex, dur);
    if (strcmp(argv[1], "af_packet_mmap") == 0) return run_af_packet_mmap(ifindex, dur);
    if (strcmp(argv[1], "raw_sendto") == 0) return run_raw_sendto(ifindex, dur);
    if (strcmp(argv[1], "af_packet_sendmmsg") == 0) return run_af_packet_sendmmsg(ifindex, dur);
    if (strcmp(argv[1], "udp_sendmmsg") == 0) return run_udp_sendmmsg(dur);
    if (strcmp(argv[1], "io_uring") == 0) return run_io_uring_send(ifindex, dur);
    return 1;
}
EOF

gcc -O3 -Wall "${WORK_DIR}/veth_io_bench.c" -o "${WORK_DIR}/veth_io_bench"
modprobe pktgen 2>/dev/null || true

setup_veth() {
    cleanup_netns
    ip netns add io-tx
    ip netns add io-rx
    ip -n io-tx link add vtx numtxqueues 1 numrxqueues 1 type veth peer name vrx numtxqueues 1 numrxqueues 1 netns io-rx
    ip -n io-tx addr add 10.200.1.1/24 dev vtx
    ip -n io-tx link set lo up
    ip -n io-tx link set vtx up
    ip -n io-rx addr add 10.200.1.2/24 dev vrx
    ip -n io-rx link set lo up
    ip -n io-rx link set vrx up
    local vrx_mac
    vrx_mac="$(ip netns exec io-rx cat /sys/class/net/vrx/address)"
    ip -n io-tx neigh replace 10.200.1.2 lladdr "${vrx_mac}" dev vtx nud permanent
    ip netns exec io-rx "${XDPERF_BIN}" run --recv --device vrx >"${WORK_DIR}/vrx.log" 2>&1 &
    RX_PID=$!
    sleep 0.5
}

OUT_JSONL="${WORK_DIR}/results.jsonl"

for r in $(seq 1 "${ROUNDS}"); do
    for m in af_xdp io_uring af_packet_sendmmsg raw_sendto af_packet_mmap udp_sendmmsg; do
        setup_veth
        res="$(ip netns exec io-tx taskset -c "${PIN_CPU}" "${WORK_DIR}/veth_io_bench" "${m}" vtx "${DURATION_S}")"
        echo "${res}" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); d['round']=${r}; print(json.dumps(d))" >> "${OUT_JSONL}"
    done

    if [ -d /proc/net/pktgen ]; then
        setup_veth
        vrx_mac="$(ip netns exec io-rx cat /sys/class/net/vrx/address)"
        ip netns exec io-tx bash -c "
            echo 'rem_device_all' > /proc/net/pktgen/kpktgend_${PIN_CPU}
            echo 'add_device vtx' > /proc/net/pktgen/kpktgend_${PIN_CPU}
            echo 'pkt_size 60' > /proc/net/pktgen/vtx
            echo 'count ${PKTGEN_PKT_COUNT}' > /proc/net/pktgen/vtx
            echo 'clone_skb 0' > /proc/net/pktgen/vtx
            echo 'dst_min 10.200.1.2' > /proc/net/pktgen/vtx
            echo 'dst_max 10.200.1.2' > /proc/net/pktgen/vtx
            echo 'dst_mac ${vrx_mac}' > /proc/net/pktgen/vtx
            echo 'udp_src_min 10000' > /proc/net/pktgen/vtx
            echo 'udp_src_max 26383' > /proc/net/pktgen/vtx
            echo 'udp_dst_min 5201' > /proc/net/pktgen/vtx
            echo 'udp_dst_max 5201' > /proc/net/pktgen/vtx
            echo 'start' > /proc/net/pktgen/pgctrl
        "
        pktgen_out="$(ip netns exec io-tx cat /proc/net/pktgen/vtx)"
        python3 - "${r}" "${pktgen_out}" >> "${OUT_JSONL}" <<'PY'
import json, re, sys
r, out = int(sys.argv[1]), sys.argv[2]
m = re.search(r"(\d+)pps", out)
pps = float(m.group(1)) if m else 0.0
print(json.dumps({"round": r, "mode": "kernel_pktgen_sweep", "pps": pps}))
PY
    fi

    setup_veth
    vrx_mac="$(ip netns exec io-rx cat /sys/class/net/vrx/address)"
    ip netns exec io-tx taskset -c "${PIN_CPU}" "${XDPERF_BIN}" run --send --device vtx \
        --plugin simpleudp.tinygo --plugin-path "${PLUGIN_PATH}" \
        --plugin-config "{\"src_ip\":\"10.200.1.1\",\"dst_ip\":\"10.200.1.2\",\"dst_mac\":\"${vrx_mac}\",\"src_port\":10000,\"dst_port\":5201,\"count\":16384,\"payload_size\":22}" \
        --parallelism 1 --cpu-mode "${PIN_CPU}" --count "${XDPERF_PKT_COUNT}" >"${WORK_DIR}/xdperf_tx.log" 2>&1
    python3 - "${r}" "${WORK_DIR}/xdperf_tx.log" >> "${OUT_JSONL}" <<'PY'
import json, re, statistics, sys
r, log_path = int(sys.argv[1]), sys.argv[2]
txt = open(log_path).read()
samples = [int(m.replace(",", "")) for m in re.findall(r"([\d,]+)\s+xmit/s", txt) if int(m.replace(",", "")) > 100000]
if len(samples) > 4:
    samples = samples[1:-1]
pps = statistics.mean(samples) if samples else 0.0
print(json.dumps({"round": r, "mode": "xdperf_live_frames", "pps": pps}))
PY
done

python3 - "${OUT_JSONL}" <<'PY'
import json, statistics, sys
from collections import defaultdict

rows = [json.loads(l) for l in open(sys.argv[1])]
by_mode = defaultdict(list)
for r in rows:
    by_mode[r["mode"]].append(r["pps"])

xdp_mean = statistics.mean(by_mode["xdperf_live_frames"])
order = [
    "xdperf_live_frames",
    "af_xdp_copy",
    "io_uring_send",
    "af_packet_sendmmsg",
    "af_packet_sendto",
    "af_packet_mmap",
    "kernel_pktgen_sweep",
    "udp_socket_sendmmsg",
]
print("=== veth 1-Core TX Packet Generation Benchmark (64B UDP, 16384 port variants) ===")
for m in order:
    vals = by_mode.get(m, [])
    if not vals:
        continue
    mean = statistics.mean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    ratio = xdp_mean / mean if mean > 0 else 0.0
    gbps = mean * 64 * 8 / 1e9
    ns = 1e9 / mean if mean > 0 else 0.0
    print(f"  {m:22s}: {mean:10.1f} ± {sd:8.1f} PPS  ({ns:6.1f} ns/pkt, {gbps:5.3f} Gbps)  [xdperf is {ratio:5.2f}x]")
PY
