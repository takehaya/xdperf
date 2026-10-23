#ifndef XDP_TCP_TEMPLATE_RX_H
#define XDP_TCP_TEMPLATE_RX_H

#include "xdp_tcp_decap.h"
#include "xdp_mixed_rx_stats.h"

static __always_inline int tcp_rx_mixed_run(struct xdp_md *ctx, const int extended)
{
    __u32 zero = 0;
    struct tcp_cfg *global = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
    struct tcp_stats *st = bpf_map_lookup_elem(&tcp_stats_map, &zero);
    struct tcp_cpu_state *cs = bpf_map_lookup_elem(&tcp_cpu_state_map, &zero);
    if (!global || !st || !cs)
        return XDP_PASS;
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct tcp_inner_packet inner = {0};
    int parsed = tcp_find_inner(ctx, &inner);
    if (parsed == 2)
        parsed = tcp_find_inner_extended(ctx, &inner);
    if (!parsed)
        goto unmatched;
    __u32 l4 = inner.l4, ip_end = inner.ip_end;
    if (l4 > 236)
        goto unmatched;
    struct tcphdr *th = data + l4;
    if ((void *)(th + 1) > end)
        goto unmatched;
    __u16 dport = bpf_ntohs(th->dest);
    if (dport < global->port_base)
        goto unmatched;
    __u32 idx = dport - global->port_base;
    if (idx >= global->flow_count || idx >= MAX_TCP_FLOWS)
        goto unmatched;
    struct tcp_flow *f = bpf_map_lookup_elem(&tcp_flow_map, &idx);
    if (!f)
        goto unmatched;
    __u32 group = f->template_id;
    struct tcp_template *t = bpf_map_lookup_elem(&tcp_template_map, &group);
    if (!t || inner.version != t->cfg.ip_version || bpf_ntohs(th->source) != t->cfg.dst_port)
        goto unmatched;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (inner.src[i] != t->cfg.dst_ip[i] || inner.dst[i] != t->cfg.src_ip[i])
            goto unmatched;
    }
    __u32 hl = th->doff * 4;
    if (hl < 20 || ip_end < l4 + hl || ip_end > inner.limit)
        return XDP_DROP;
    struct tcp_rx_info in = {.seq = bpf_ntohl(th->seq),
                             .ack = bpf_ntohl(th->ack_seq),
                             .payload_len = ip_end - l4 - hl,
                             .win = bpf_ntohs(th->window),
                             .dport = dport,
                             .doff = th->doff,
                             .flags = ((__u8 *)th)[13],
                             .wscale = 0xff};
    struct tcp_rx_timestamp ts = {0};
    struct tcp_tx_extra extra = {0};
    if (extended && mixed_has_timestamps && t->timestamps && tcp_parse_timestamp(ctx, l4, in.doff, &ts) < 0)
        return XDP_DROP;
    if ((in.flags & (TCPF_SYN | TCPF_ACK)) == (TCPF_SYN | TCPF_ACK) && in.doff > 5) {
        tcp_parse_syn_opts(ctx, l4, in.doff, &in.wscale, &in.mss);
        __u32 option_bytes = t->data_len;
        if (extended && mixed_has_timestamps && t->timestamps && ts.has_timestamp)
            option_bytes += 12;
        if (in.mss)
            in.mss = in.mss > option_bytes ? in.mss - option_bytes : 1;
    }
    __sync_fetch_and_add(&f->rx_pkts, 1);
    struct tcp_rx_resp resp = {0};
    tcp_rx_update(f, st, &in, t->cfg.mss, bpf_ktime_get_ns(), &resp, &ts, &extra, extended && mixed_has_timestamps && t->timestamps,
                  1);
    if (!resp.flags)
        return XDP_DROP;
    struct tcp_tx_action act = {.seq = resp.seq, .ack = resp.ack, .flags = resp.flags, .src_port = dport};
    bpf_spin_lock(&f->lock);
    act.ip_id = f->ip_id++;
    bpf_spin_unlock(&f->lock);
    int built;
    if (extended)
        built = tcp_template_build_ext(ctx, t, cs, &act, &extra);
    else
        built = tcp_template_build(ctx, t, cs, &act);
    if (built >= 0 && extended)
        built = tcp_template_finish(ctx, t, &act, &extra);
    if (built < 0) {
        st->build_errors++;
        return XDP_DROP;
    }
    if (resp.flags == TCPF_ACK)
        st->acks_sent++;
    __sync_fetch_and_add(&f->rx_replies, 1);
    st->rx_replies++;
    return XDP_TX;
unmatched:
    if (!extended)
        mixed_rx_unmatched(ctx);
    if (inner.neighbor)
        return XDP_PASS;
    if (inner.outer_udp) {
        struct mixed_cfg *mix = bpf_map_lookup_elem(&mixed_cfg_map, &zero);
        if (mix && mix->receive)
            bpf_tail_call(ctx, &mixed_progs, 3);
    }
    return XDP_PASS;
}
SEC("xdp")
int xdp_rx_tcp_mixed(struct xdp_md *ctx)
{
    return tcp_rx_mixed_run(ctx, 0);
}
SEC("xdp")
int xdp_rx_tcp_mixed_ext(struct xdp_md *ctx)
{
    return tcp_rx_mixed_run(ctx, 1);
}
#endif
