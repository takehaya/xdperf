#ifndef XDP_TCP_TIMESTAMP_H
#define XDP_TCP_TIMESTAMP_H

// Timestamp parsing is absent from programs specialized without timestamps.
// Forty NOPs are legal; the bound therefore counts bytes, not just TLVs.
static __noinline int tcp_parse_timestamp(struct xdp_md *ctx, __u32 l4, __u32 doff, struct tcp_rx_info *in)
{
    __u32 off = l4 + 20, limit = l4 + doff * 4;
    for (int i = 0; i < 40; i++) {
        if (off >= limit)
            return 0;
        __u8 h[2];
        if (bpf_xdp_load_bytes(ctx, off, h, 1) < 0)
            return -1;
        if (h[0] == 0)
            return 0;
        if (h[0] == 1) {
            off++;
            continue;
        }
        if (off + 2 > limit || bpf_xdp_load_bytes(ctx, off, h, 2) < 0 || h[1] < 2 || off + h[1] > limit)
            return -1;
        if (h[0] == 8) {
            if (h[1] != 10 || in->has_timestamp)
                return -1;
            __u8 ts[8];
            if (bpf_xdp_load_bytes(ctx, off + 2, ts, 8) < 0)
                return -1;
            in->tsval = ((__u32)ts[0] << 24) | ((__u32)ts[1] << 16) | ((__u32)ts[2] << 8) | ts[3];
            in->has_timestamp = 1;
        }
        off += h[1];
    }
    return 0;
}

// now was captured outside the lock. A concurrent RX/TX may have newer time.
static __always_inline __u32 tcp_timestamp_clock(struct tcp_flow *f, __u64 now)
{
    __u32 clock = now / 1000000;
    if ((__s32)(clock - f->ts_clock) < 0)
        clock = f->ts_clock;
    f->ts_clock = clock;
    return clock;
}
#endif
