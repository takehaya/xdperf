#ifndef XDP_TCP_DECAP_H
#define XDP_TCP_DECAP_H
struct tcp_inner_packet {
    __u32 l4;
    __u32 ip_end;
    __u32 limit;
    __u32 src[4];
    __u32 dst[4];
    __u8 version;
    __u8 outer_udp;
    __u8 neighbor;
};

static __noinline int tcp_geneve_options(struct xdp_md *ctx, __u32 off, __u32 end)
{
    __u8 h[4];
#pragma unroll
    for (int i = 0; i < 41; i++) {
        if (off >= end)
            return off == end;
        if (off > 232 || off + 4 > end || bpf_xdp_load_bytes(ctx, off, h, 4) < 0 || (h[2] & 0x80) || (h[3] & 0xe0))
            return 0;
        off += 4 + (h[3] & 31) * 4;
    }
    return off == end;
}

// Cold tunnel paths are separate subprograms, so their option/label walks
// are not duplicated in each unrolled IP layer.
static __noinline int tcp_mpls_end(struct xdp_md *ctx, __u32 off, __u32 limit)
{
    __u8 h[4];
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (off > 232 || off + 4 > limit || bpf_xdp_load_bytes(ctx, off, h, 4) < 0)
            return 0;
        off += 4;
        if (h[2] & 1)
            return off;
    }
    return 0;
}

static __always_inline __u16 tcp_raw_ip_proto(struct xdp_md *ctx, __u32 off, __u32 limit)
{
    __u8 version;
    if (off > 236 || off >= limit || bpf_xdp_load_bytes(ctx, off, &version, 1) < 0)
        return 0;
    return version >> 4 == 4 ? ETH_P_IP : (version >> 4 == 6 ? ETH_P_IPV6 : 0);
}

struct tcp_decap_cursor {
    __u32 off;
    __u32 limit;
    __u16 proto;
};

static __noinline int tcp_decap_ip_tunnel(struct xdp_md *ctx, struct tcp_decap_cursor *c, __u8 next)
{
    __u32 off = c->off, limit = c->limit;
    __u8 h[8];
    if (off > 236)
        return 0;
    if (next == IPPROTO_ROUTING) {
        if (off + 8 > limit || bpf_xdp_load_bytes(ctx, off, h, 8) < 0 || h[2] != 4)
            return 0;
        __u32 len = ((__u32)h[1] + 1) * 8;
        if (len < 8 + 16 * ((__u32)h[4] + 1) || (__u32)h[3] > (__u32)h[4] + 1 || off + len > limit)
            return 0;
        off += len;
        next = h[0];
        // An SRH attached to TCP itself needs different pseudoheader semantics.
        if (next != IPPROTO_IPIP && next != IPPROTO_IPV6 && next != 143)
            return 0;
    }
    if (next == IPPROTO_GRE) {
        if (off + 4 > limit || bpf_xdp_load_bytes(ctx, off, h, 4) < 0 || (h[0] & ~0x20) || h[1])
            return 0;
        c->proto = ((__u16)h[2] << 8) | h[3];
        off += (h[0] & 0x20) ? 8 : 4;
        if (off > limit)
            return 0;
    } else if (next == IPPROTO_IPIP) {
        c->proto = ETH_P_IP;
    } else if (next == IPPROTO_IPV6) {
        c->proto = ETH_P_IPV6;
    } else if (next == 143) {
        c->proto = 0x6558;
    } else {
        return 0;
    }
    if (off > 236)
        return 0;
    c->off = off;
    return 1;
}

static __noinline int tcp_decap_gtpu(struct xdp_md *ctx, struct tcp_decap_cursor *c)
{
    __u32 off = c->off;
    __u8 h[8];
    if (off > 228 || off + 8 > c->limit || bpf_xdp_load_bytes(ctx, off, h, 8) < 0 || (h[0] & 0xf0) != 0x30 || h[1] != 0xff)
        return 0;
    __u8 flags = h[0];
    __u32 limit = off + 8 + (((__u16)h[2] << 8) | h[3]);
    if (limit > c->limit)
        return 0;
    off += 8;
    if (flags & 7) {
        if (off > 232 || off + 4 > limit || bpf_xdp_load_bytes(ctx, off, h, 4) < 0)
            return 0;
        // TS 29.281: ignore the spare bit and unused optional fields on RX.
        __u8 ext = (flags & 4) ? h[3] : 0;
        off += 4;
#pragma unroll
        for (int i = 0; i < 8; i++) {
            if (!ext)
                break;
            if (off > 232 || off >= limit || bpf_xdp_load_bytes(ctx, off, h, 1) < 0)
                return 0;
            __u32 len = (__u32)h[0] * 4;
            if (!len || off + len > limit || off + len > 236)
                return 0;
            off += len;
            if (bpf_xdp_load_bytes(ctx, off - 1, &ext, 1) < 0)
                return 0;
        }
        if (ext)
            return 0;
    }
    c->proto = tcp_raw_ip_proto(ctx, off, limit);
    c->off = off;
    c->limit = limit;
    return c->proto != 0;
}

// Fixed-size helper reads avoid compiler re-association of packet pointers
// across nested, variable-size envelopes on older verifiers.
// Global subprograms are verified once, independently of their callers. Keep
// a single layer here instead of multiplying tunnel branches across five copies.
__noinline int tcp_parse_layer(struct xdp_md *ctx, struct tcp_inner_packet *out, struct tcp_decap_cursor *cursor)
{
    if (!out || !cursor)
        return 0;
    __u32 off = cursor->off, limit = cursor->limit;
    __u16 proto = cursor->proto;
    __u8 h[40];
    __u8 outer = off == 0;
    if (off > 236)
        return 0;
    if (proto == 0x6558) {
        if (off + 14 > limit || bpf_xdp_load_bytes(ctx, off, h, 14) < 0)
            return 0;
        proto = ((__u16)h[12] << 8) | h[13];
        off += 14;
#pragma unroll
        for (int tag = 0; tag < 2; tag++) {
            if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
                if (off + 4 > limit || bpf_xdp_load_bytes(ctx, off, h, 4) < 0)
                    return 0;
                proto = ((__u16)h[2] << 8) | h[3];
                off += 4;
            }
        }
    }
    if (!outer && proto == ETH_P_ARP) {
        out->neighbor = 1;
        return 0;
    }
    if (proto == ETH_P_MPLS_UC || proto == ETH_P_MPLS_MC) {
        int mpls_end = tcp_mpls_end(ctx, off, limit);
        if (!mpls_end)
            return 0;
        off = mpls_end;
        proto = tcp_raw_ip_proto(ctx, off, limit);
    }
    if (off > 216)
        return 0;
    __u32 ip_end;
    __u8 next;
    if (proto == ETH_P_IP) {
        if (off + 20 > limit || bpf_xdp_load_bytes(ctx, off, h, 20) < 0)
            return 0;
        // Preserve legacy outer UDP accounting even when this TCP parser
        // cannot inspect the packet (e.g. IPv4 options or fragments).
        if (outer && h[9] == IPPROTO_UDP)
            out->outer_udp = 1;
        if (h[0] != 0x45 || (h[6] & 0x3f) || h[7])
            return 0;
        __builtin_memcpy(out->src, h + 12, 4);
        __builtin_memcpy(out->dst, h + 16, 4);
        out->src[1] = out->src[2] = out->src[3] = 0;
        out->dst[1] = out->dst[2] = out->dst[3] = 0;
        out->version = 4;
        next = h[9];
        ip_end = off + (((__u16)h[2] << 8) | h[3]);
        off += 20;
    } else if (proto == ETH_P_IPV6) {
        if (off + 40 > limit || bpf_xdp_load_bytes(ctx, off, h, 40) < 0)
            return 0;
        if (outer && h[6] == IPPROTO_UDP)
            out->outer_udp = 1;
        if (h[0] >> 4 != 6)
            return 0;
        __builtin_memcpy(out->src, h + 8, 16);
        __builtin_memcpy(out->dst, h + 24, 16);
        out->version = 6;
        next = h[6];
        ip_end = off + 40 + (((__u16)h[4] << 8) | h[5]);
        off += 40;
    } else {
        return 0;
    }
    if (next == IPPROTO_TCP) {
        out->l4 = off;
        out->ip_end = ip_end;
        out->limit = limit;
        return 1;
    }
    if (!outer && out->version == 6 && next == IPPROTO_ICMPV6 && ip_end <= limit && off < ip_end &&
        bpf_xdp_load_bytes(ctx, off, h, 1) == 0 && h[0] >= 133 && h[0] <= 137) {
        out->neighbor = 1;
        return 0;
    }
    if (next != IPPROTO_UDP) {
        if (ip_end > limit || off > ip_end || (next == IPPROTO_ROUTING && out->version != 6))
            return 0;
        struct tcp_decap_cursor c = {.off = off, .limit = ip_end};
        if (!tcp_decap_ip_tunnel(ctx, &c, next))
            return 0;
        off = c.off;
        proto = c.proto;
        limit = ip_end;
        goto next_layer;
    }
    if (ip_end > limit || off + 8 > ip_end || off > 228 || bpf_xdp_load_bytes(ctx, off, h, 8) < 0)
        return 0;
    __u32 udp_end = off + (((__u16)h[4] << 8) | h[5]);
    __u16 port = ((__u16)h[2] << 8) | h[3];
    if (udp_end > ip_end || udp_end < off + 16)
        return 0;
    off += 8;
    limit = udp_end;
    if (bpf_xdp_load_bytes(ctx, off, h, 8) < 0)
        return 0;
    if (port == 4789) {
        if (h[0] != 8 || h[1] || h[2] || h[3] || h[7])
            return 0;
        off += 8;
        proto = 0x6558;
    } else if (port == 6081) {
        if (h[0] >> 6 || h[1] || h[7])
            return 0;
        __u32 opt_end = off + 8 + (h[0] & 63) * 4;
        proto = ((__u16)h[2] << 8) | h[3];
        off += 8;
        if (opt_end > limit || opt_end > 236)
            return 0;
        if (!tcp_geneve_options(ctx, off, opt_end))
            return 0;
        off = opt_end;
    } else if (port == 2152) {
        struct tcp_decap_cursor c = {.off = off, .limit = limit};
        if (!tcp_decap_gtpu(ctx, &c))
            return 0;
        off = c.off;
        limit = c.limit;
        proto = c.proto;
    } else {
        return 0;
    }
next_layer:
    cursor->off = off;
    cursor->limit = limit;
    cursor->proto = proto;
    return 2;
}

static __noinline int tcp_find_inner(struct xdp_md *ctx, struct tcp_inner_packet *out)
{
    __u32 limit = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    asm volatile("" : "+r"(limit));
    struct tcp_decap_cursor cursor = {.limit = limit, .proto = 0x6558};
#pragma unroll
    for (int depth = 0; depth < 5; depth++) {
        int result = tcp_parse_layer(ctx, out, &cursor);
        if (result != 2)
            return result;
    }
    return 0;
}
#endif
