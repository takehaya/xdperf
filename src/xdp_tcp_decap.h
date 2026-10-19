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
};

static __noinline int tcp_geneve_options(struct xdp_md *ctx, __u32 off, __u32 end)
{
    __u8 h[4];
#pragma unroll
    for (int i = 0; i < 40; i++) {
        if (off >= end)
            return off == end;
        if (off > 232 || off + 4 > end || bpf_xdp_load_bytes(ctx, off, h, 4) < 0 || (h[2] & 0x80) || (h[3] & 0xe0))
            return 0;
        off += 4 + (h[3] & 31) * 4;
    }
    return off == end;
}

// Fixed-size helper reads avoid compiler re-association of packet pointers
// across nested, variable-size envelopes on older verifiers.
static __noinline int tcp_find_inner(struct xdp_md *ctx, struct tcp_inner_packet *out)
{
    __u32 off = 0;
    __u32 limit = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    asm volatile("" : "+r"(limit));
    __u16 proto = 0x6558;
    __u8 h[40];
#pragma unroll
    for (int depth = 0; depth < 5; depth++) {
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
        if (off > 216)
            return 0;
        __u32 ip_end;
        __u8 next;
        if (proto == ETH_P_IP) {
            if (off + 20 > limit || bpf_xdp_load_bytes(ctx, off, h, 20) < 0 || h[0] != 0x45 || (h[6] & 0x3f) || h[7])
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
            if (off + 40 > limit || bpf_xdp_load_bytes(ctx, off, h, 40) < 0 || h[0] >> 4 != 6)
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
        if (depth == 0 && next == IPPROTO_UDP)
            out->outer_udp = 1;
        if (next == IPPROTO_TCP) {
            out->l4 = off;
            out->ip_end = ip_end;
            out->limit = limit;
            return 1;
        }
        if (next != IPPROTO_UDP || ip_end > limit || off + 8 > ip_end || off > 228 || bpf_xdp_load_bytes(ctx, off, h, 8) < 0)
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
        } else {
            return 0;
        }
    }
    return 0;
}
#endif
