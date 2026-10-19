#ifndef XDP_TCP_TEMPLATE_EXT_H
#define XDP_TCP_TEMPLATE_EXT_H

#include "xdp_tcp_encap.h"
#include "xdp_tcp_payload.h"

// Mixed TCP has a separate builder, leaving standalone TCP's instructions intact.
__noinline int tcp_template_build_ext(struct xdp_md *ctx, const struct tcp_template *t, struct tcp_cpu_state *cs,
                                      const struct tcp_tx_action *a, struct tcp_tx_extra *extra)
{
    if (!t || !cs || !a || !extra)
        return -1;
    const struct tcp_cfg *cfg = &t->cfg;
    __u32 l3 = cfg->l3_off, l4 = cfg->l4_off;
    __u32 opts = (a->flags & TCPF_SYN) ? t->syn_len : t->data_len;
    if (l3 > 216 || l4 > 236 || opts > 40 || (opts & 3))
        return -1;
    __u32 staticopts = opts;
    __u32 tslen = 0;
    if (mixed_has_timestamps && t->timestamps && extra->timestamps) {
        tslen = 12;
        opts += tslen;
        if (opts > 40)
            return -1;
    }
    __u32 tcp_len = 20 + opts + a->len;
    __u32 target = l4 + tcp_len;
    if (target > MAX_PACKET_SIZE)
        return -1;
    // Discard recycled packet data, including all previous TCP options.
    __u32 old = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    asm volatile("" : "+r"(old));
    if (bpf_xdp_adjust_tail(ctx, (int)(l4 + 20) - (int)old) < 0)
        return -1;
    if (target != l4 + 20 && bpf_xdp_adjust_tail(ctx, (int)(opts + a->len)) < 0)
        return -1;

    __u8 *prefix_data = (void *)(long)ctx->data;
    void *prefix_end = (void *)(long)ctx->data_end;
#pragma unroll
    for (int i = 0; i < 256; i += 8) {
        if (i < l4) {
            if ((void *)(prefix_data + i + 8) > prefix_end)
                return -1;
            __builtin_memcpy(prefix_data + i, t->prefix + i, 8);
        }
    }
    __u32 payload_sum = 0;
    if (mixed_has_payload && a->len) {
        __u32 id = t->payload_id;
        const struct tcp_payload *p = bpf_map_lookup_elem(&tcp_payload_map, &id);
        if (!p)
            return -1;
        if (p->period) {
            int result = tcp_payload_sum(a->len, extra->stream_offset, p);
            if (result < 0)
                return -1;
            payload_sum = result;
        }
    }
    __u8 ts[12] = {1, 1, 8, 10};
    __u32 ts_sum = 0;
    if (mixed_has_timestamps && tslen) {
        put_be32(ts + 4, extra->tsval);
        put_be32(ts + 8, extra->tsecr);
        __u64 sum = 0;
        SUM16_BUF(sum, ts, 12);
        ts_sum = sum;
        if (bpf_xdp_store_bytes(ctx, l4 + 20, ts, 12) < 0)
            return -1;
    }
    __u8 th[20] = {0};
    __builtin_memcpy(th, t->tcp_header, 20);
    const __u8 *options = (a->flags & TCPF_SYN) ? t->syn_options : t->data_options;
    put_be16(th, a->src_port);
    put_be16(th + 2, cfg->dst_port);
    put_be32(th + 4, a->seq);
    put_be32(th + 8, a->ack);
    th[12] = (th[12] & 0x0e) | (((20 + opts) / 4) << 4); // NS is ECN-owned
    th[13] = a->flags;
    put_be16(th + 14, 65535);
    th[16] = th[17] = 0;
    __u64 sum = cfg->pseudo_sum + IPPROTO_TCP + tcp_len + payload_sum + ts_sum;
    SUM16_BUF(sum, th, 20);
    sum += (a->flags & TCPF_SYN) ? t->syn_sum : t->data_sum;
    put_be16(th + 16, tcp_csum_fold(sum));
    if (bpf_xdp_store_bytes(ctx, l4, th, 20) < 0)
        return -1;
    __u8 *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    __u8 *op = data + l4 + 20 + tslen;
#pragma unroll
    for (int i = 0; i < 40; i += 4) {
        if (i < staticopts) {
            if ((void *)(op + i + 4) > end)
                return -1;
            __builtin_memcpy(op + i, options + i, 4);
        }
    }
    // Variable offsets address the map, never a stack array.
    __u8 ih[40];
    __builtin_memcpy(ih, t->prefix + l3, 40);
    __u16 ip_id = cfg->ip_id_shared ? (__u16)cs->ip_id++ : a->ip_id;
    extra->ip_id = ip_id;
    if (cfg->ip_version == 4) {
        ih[1] &= 0xfc;
        put_be16(ih + 2, 20 + tcp_len);
        put_be16(ih + 4, ip_id);
        ih[10] = ih[11] = 0;
        __u64 isum = 0;
        SUM16_BUF(isum, ih, 20);
        put_be16(ih + 10, tcp_csum_fold(isum));
        if (bpf_xdp_store_bytes(ctx, l3, ih, 20) < 0)
            return -1;
    } else {
        ih[1] &= 0xcf;
        put_be16(ih + 4, tcp_len);
        if (bpf_xdp_store_bytes(ctx, l3, ih, 40) < 0)
            return -1;
    }
    return 0;
}

// Run envelope fixups after releasing the builder's stack frame. Keep the
// exact shared/per-flow IPv4 ID selected by the builder in optional state.
static __always_inline int tcp_template_finish(struct xdp_md *ctx, const struct tcp_template *t, const struct tcp_tx_action *a,
                                               const struct tcp_tx_extra *extra)
{
    if (mixed_max_lengths == 0)
        return 0;
    __u32 options = (a->flags & TCPF_SYN) ? t->syn_len : t->data_len;
    if (mixed_has_timestamps && extra->timestamps)
        options += 12;
    return tcp_encap_patch(ctx, t, 20 + options + a->len, (__u32)a->src_port - t->cfg.port_base, extra->ip_id);
}
#endif
