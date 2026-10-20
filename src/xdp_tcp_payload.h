#ifndef XDP_TCP_PAYLOAD_H
#define XDP_TCP_PAYLOAD_H

struct tcp_payload_copy {
    struct xdp_md *ctx;
    const struct tcp_payload *pattern;
    __u32 offset, len, start, period;
    int error;
};

static long tcp_payload_copy_chunk(__u32 index, void *opaque)
{
    struct tcp_payload_copy *c = opaque;
    __u32 off = index * 16;
    if (off >= c->len || !c->period)
        return 1;
    __u8 chunk[16] = {0};
#pragma unroll
    for (int i = 0; i < 16; i++) {
        __u32 at = (c->start + off + i) % c->period;
        asm volatile("" : "+r"(at));
        chunk[i] = c->pattern->bytes[at & 511];
    }
    if (c->len - off >= 16) {
        if (bpf_xdp_store_bytes(c->ctx, c->offset + off, chunk, 16) < 0) {
            c->error = 1;
            return 1;
        }
        return 0;
    }
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (off + i < c->len && bpf_xdp_store_bytes(c->ctx, c->offset + off + i, chunk + i, 1) < 0) {
            c->error = 1;
            return 1;
        }
    }
    return 0;
}

// Prefix sums use the byte phase of the even period. Subtracting two prefixes
// gives the segment sum; rotate its byte phase when the start index is odd.
static __always_inline __u32 tcp_payload_prefix(const struct tcp_payload *p, __u32 n)
{
    asm volatile("" : "+r"(n));
    n &= 511;
    __u32 sum = p->sums[n / 2];
    if (n & 1)
        sum += (__u32)p->bytes[(n - 1) & 511] << 8;
    return sum;
}

static __always_inline int tcp_payload_sum(__u32 len, __u64 stream, const struct tcp_payload *p)
{
    if (!p)
        return -1;
    __u32 period = p->period;
    if (!period || period > 512 || (period & 1) || len > MAX_PACKET_SIZE)
        return -1;
    __u32 words = (period / 2) & 511;
    if (words > 256)
        return -1;
    __u32 start = stream % period;
    __u32 total = start + len;
    __u64 sum = (__u64)(total / period) * p->sums[words];
    // A multiple of 65535 avoids unsigned underflow during prefix subtraction.
    sum += tcp_payload_prefix(p, total % period) + 65535U * 512U - tcp_payload_prefix(p, start);
    __u16 folded = ~tcp_csum_fold(sum);
    if (start & 1)
        folded = (folded << 8) | (folded >> 8);

    return folded;
}

// Called after the builder has returned, keeping cumulative BPF stack below 512.
static __noinline int tcp_payload_write(struct xdp_md *ctx, __u32 offset, __u32 len, __u64 stream, const struct tcp_payload *p)
{
    __u32 period = p->period;
    if (!period || period > 512 || len > MAX_PACKET_SIZE)
        return -1;
    struct tcp_payload_copy copy = {
        .ctx = ctx, .pattern = p, .offset = offset, .len = len, .start = stream % period, .period = period};
    bpf_loop((len + 15) / 16, tcp_payload_copy_chunk, &copy, 0);
    if (copy.error)
        return -1;
    return 0;
}
#endif
