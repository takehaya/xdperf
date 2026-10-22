#ifndef XDP_MIXED_RX_STATS_H
#define XDP_MIXED_RX_STATS_H

// Keep RX classification counters separate from TCP flow statistics.
enum mixed_rx_reason {
    MIXED_RX_PARSE_FAILED,
    MIXED_RX_PORT_OUTSIDE,
    MIXED_RX_TUPLE_MISMATCH,
    MIXED_RX_NEIGHBOR,
    MIXED_RX_OTHER,
    MIXED_RX_INVALID_TCP,
    MIXED_RX_REASONS,
};
struct mixed_rx_stats {
    __u64 counts[MIXED_RX_REASONS];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mixed_rx_stats);
} mixed_rx_stats_map SEC(".maps");

static __noinline void mixed_rx_count(__u32 reason)
{
    __u32 zero = 0;
    struct mixed_rx_stats *st = bpf_map_lookup_elem(&mixed_rx_stats_map, &zero);
    if (st && reason < MIXED_RX_REASONS)
        st->counts[reason]++;
}

// Inspect the terminal layer only on the unmatched path. This supplements the
// TCP walker, which intentionally stops early on ordinary non-TCP traffic.
static __noinline int mixed_rx_terminal(struct xdp_md *ctx, const struct tcp_decap_cursor *c)
{
    __u32 off = c->off, limit = c->limit;
    __u16 proto = c->proto;
    __u8 h[40];
    if (proto == 0x6558) {
        if (off > 236 || off + 14 > limit || bpf_xdp_load_bytes(ctx, off, h, 14) < 0)
            return MIXED_RX_PARSE_FAILED;
        proto = ((__u16)h[12] << 8) | h[13];
        off += 14;
#pragma unroll
        for (int i = 0; i < 2; i++) {
            if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
                if (off > 236 || off + 4 > limit || bpf_xdp_load_bytes(ctx, off, h, 4) < 0)
                    return MIXED_RX_PARSE_FAILED;
                proto = ((__u16)h[2] << 8) | h[3];
                off += 4;
            }
        }
    }
    if (proto == ETH_P_MPLS_UC || proto == ETH_P_MPLS_MC) {
        int mpls_end = tcp_mpls_end(ctx, off, limit);
        if (!mpls_end)
            return MIXED_RX_PARSE_FAILED;
        off = mpls_end;
        proto = tcp_raw_ip_proto(ctx, off, limit);
    }
    if (proto == ETH_P_ARP)
        return MIXED_RX_NEIGHBOR;
    __u8 next;
    __u32 ip_end;
    if (off > 216)
        return MIXED_RX_PARSE_FAILED;
    if (proto == ETH_P_IP) {
        if (off + 20 > limit || bpf_xdp_load_bytes(ctx, off, h, 20) < 0 || h[0] != 0x45 || (h[6] & 0x3f) || h[7])
            return MIXED_RX_PARSE_FAILED;
        next = h[9];
        ip_end = off + (((__u16)h[2] << 8) | h[3]);
        off += 20;
    } else if (proto == ETH_P_IPV6) {
        if (off + 40 > limit || bpf_xdp_load_bytes(ctx, off, h, 40) < 0 || h[0] >> 4 != 6)
            return MIXED_RX_PARSE_FAILED;
        next = h[6];
        ip_end = off + 40 + (((__u16)h[4] << 8) | h[5]);
        off += 40;
    } else {
        return MIXED_RX_PARSE_FAILED;
    }
    if (ip_end < off || ip_end > limit)
        return MIXED_RX_PARSE_FAILED;
    if (next == IPPROTO_ICMPV6 && proto == ETH_P_IPV6 && off < ip_end && bpf_xdp_load_bytes(ctx, off, h, 1) == 0 && h[0] >= 133 &&
        h[0] <= 137)
        return MIXED_RX_NEIGHBOR;
    if (next == IPPROTO_ICMP || next == IPPROTO_ICMPV6)
        return MIXED_RX_OTHER;
    if (next == IPPROTO_UDP && off <= 228 && off + 8 <= ip_end && bpf_xdp_load_bytes(ctx, off, h, 8) == 0) {
        __u32 udp_end = off + (((__u16)h[4] << 8) | h[5]);
        __u16 port = ((__u16)h[2] << 8) | h[3];
        if (udp_end >= off + 8 && udp_end <= ip_end && port != 4789 && port != 6081 && port != 2152)
            return MIXED_RX_OTHER;
    }
    return MIXED_RX_PARSE_FAILED;
}

static __noinline void mixed_rx_outer(struct xdp_md *ctx)
{
    __u32 limit = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    asm volatile("" : "+r"(limit));
    struct tcp_decap_cursor c = {.limit = limit, .proto = 0x6558};
    mixed_rx_count(mixed_rx_terminal(ctx, &c));
}

static __noinline void mixed_rx_unmatched(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct tcp_inner_packet inner = {0};
    __u32 limit = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    asm volatile("" : "+r"(limit));
    struct tcp_decap_cursor c = {.limit = limit, .proto = 0x6558};
    int parsed = 0;
#pragma unroll
    for (int depth = 0; depth < 5; depth++) {
        parsed = tcp_parse_layer(ctx, &inner, &c);
        if (parsed != 2)
            break;
    }
    __u32 reason = MIXED_RX_PARSE_FAILED;
    if (inner.neighbor)
        reason = MIXED_RX_NEIGHBOR;
    else if (!parsed)
        reason = mixed_rx_terminal(ctx, &c);
    else if (parsed == 1 && inner.l4 <= 236) {
        __u8 th[20];
        if (inner.limit <= limit && inner.ip_end <= inner.limit && inner.l4 + 20 <= inner.ip_end &&
            bpf_xdp_load_bytes(ctx, inner.l4, th, 20) == 0 && (th[12] >> 4) >= 5 && inner.l4 + (th[12] >> 4) * 4 <= inner.ip_end) {
            struct tcp_cfg *cfg = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
            __u16 dport = ((__u16)th[2] << 8) | th[3];
            if (cfg) {
                __u32 idx = (__u32)dport - cfg->port_base;
                reason = dport < cfg->port_base || idx >= cfg->flow_count || idx >= MAX_TCP_FLOWS ? MIXED_RX_PORT_OUTSIDE
                                                                                                  : MIXED_RX_TUPLE_MISMATCH;
            }
        }
    }
    mixed_rx_count(reason);
}
#endif
