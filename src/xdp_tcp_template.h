#ifndef XDP_TCP_TEMPLATE_H
#define XDP_TCP_TEMPLATE_H

#include "xdp_tcp_encap.h"

// Mixed TCP has a separate builder, leaving standalone TCP's instructions intact.
static __noinline int tcp_template_build(struct xdp_md *ctx, const struct tcp_template *t, struct tcp_cpu_state *cs,
                                         const struct tcp_tx_action *a)
{
    if (!t)
        return -1;
    const struct tcp_cfg *cfg = &t->cfg;
    __u32 l3 = cfg->l3_off, l4 = cfg->l4_off;
    __u32 opts = (a->flags & TCPF_SYN) ? t->syn_len : t->data_len;
    if (l3 > 216 || l4 > 236 || opts > 40 || (opts & 3))
        return -1;
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
    __u64 sum = cfg->pseudo_sum + IPPROTO_TCP + tcp_len;
    SUM16_BUF(sum, th, 20);
    sum += (a->flags & TCPF_SYN) ? t->syn_sum : t->data_sum;
    put_be16(th + 16, tcp_csum_fold(sum));
    if (bpf_xdp_store_bytes(ctx, l4, th, 20) < 0)
        return -1;
    __u8 *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    __u8 *op = data + l4 + 20;
#pragma unroll
    for (int i = 0; i < 40; i++) {
        if (i < opts) {
            if ((void *)(op + i + 1) > end)
                return -1;
            op[i] = options[i];
        }
    }
    // Variable offsets address the map, never a stack array.
    __u8 ih[40];
    __builtin_memcpy(ih, t->prefix + l3, 40);
    __u16 ip_id = cfg->ip_id_shared ? (__u16)cs->ip_id++ : a->ip_id;
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
    return tcp_encap_patch(ctx, t, tcp_len, (__u32)a->src_port - cfg->port_base, ip_id);
}
#endif
