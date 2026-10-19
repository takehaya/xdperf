#ifndef XDP_TCP_TEMPLATE_RX_H
#define XDP_TCP_TEMPLATE_RX_H

SEC("xdp")
int xdp_rx_tcp_mixed(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct tcp_cfg *global = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
    struct tcp_stats *st = bpf_map_lookup_elem(&tcp_stats_map, &zero);
    struct tcp_cpu_state *cs = bpf_map_lookup_elem(&tcp_cpu_state_map, &zero);
    if (!global || !st || !cs)
        return XDP_PASS;
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return XDP_PASS;
    __u16 proto = eth->h_proto;
    __u32 l3 = 14;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *v = data + l3;
            if ((void *)(v + 1) > end)
                return XDP_PASS;
            proto = v->h_vlan_encapsulated_proto;
            l3 += 4;
        }
    }
    __u32 l4, ip_end;
    __u8 version;
    __u32 src[4] = {0}, dst[4] = {0};
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + l3;
        if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_TCP ||
            (bpf_ntohs(ip->frag_off) & 0x3fff))
            return XDP_PASS;
        src[0] = ip->saddr;
        dst[0] = ip->daddr;
        l4 = l3 + 20;
        ip_end = l3 + bpf_ntohs(ip->tot_len);
        version = 4;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip = data + l3;
        if ((void *)(ip + 1) > end || ip->version != 6 || ip->nexthdr != IPPROTO_TCP)
            return XDP_PASS;
        __builtin_memcpy(src, &ip->saddr, 16);
        __builtin_memcpy(dst, &ip->daddr, 16);
        l4 = l3 + 40;
        ip_end = l4 + bpf_ntohs(ip->payload_len);
        version = 6;
    } else {
        return XDP_PASS;
    }
    struct tcphdr *th = data + l4;
    if ((void *)(th + 1) > end)
        return XDP_PASS;
    __u16 dport = bpf_ntohs(th->dest);
    if (dport < global->port_base)
        return XDP_PASS;
    __u32 idx = dport - global->port_base;
    if (idx >= global->flow_count || idx >= MAX_TCP_FLOWS)
        return XDP_PASS;
    struct tcp_flow *f = bpf_map_lookup_elem(&tcp_flow_map, &idx);
    if (!f)
        return XDP_PASS;
    __u32 group = f->template_id;
    struct tcp_template *t = bpf_map_lookup_elem(&tcp_template_map, &group);
    if (!t || version != t->cfg.ip_version || bpf_ntohs(th->source) != t->cfg.dst_port)
        return XDP_PASS;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (src[i] != t->cfg.dst_ip[i] || dst[i] != t->cfg.src_ip[i])
            return XDP_PASS;
    }
    __u32 hl = th->doff * 4;
    if (hl < 20 || ip_end < l4 + hl || ip_end > ctx->data_end - ctx->data)
        return XDP_DROP;
    struct tcp_rx_info in = {.seq = bpf_ntohl(th->seq),
                             .ack = bpf_ntohl(th->ack_seq),
                             .payload_len = ip_end - l4 - hl,
                             .win = bpf_ntohs(th->window),
                             .dport = dport,
                             .doff = th->doff,
                             .flags = ((__u8 *)th)[13],
                             .wscale = 0xff};
    if ((in.flags & (TCPF_SYN | TCPF_ACK)) == (TCPF_SYN | TCPF_ACK) && in.doff > 5) {
        tcp_parse_syn_opts(ctx, l4, in.doff, &in.wscale, &in.mss);
        if (in.mss)
            in.mss = in.mss > t->data_len ? in.mss - t->data_len : 1;
    }
    __sync_fetch_and_add(&f->rx_pkts, 1);
    struct tcp_rx_resp resp = {0};
    tcp_rx_update(f, st, &in, t->cfg.mss, bpf_ktime_get_ns(), &resp);
    if (!resp.flags)
        return XDP_DROP;
    struct tcp_tx_action act = {.seq = resp.seq, .ack = resp.ack, .flags = resp.flags, .src_port = dport};
    bpf_spin_lock(&f->lock);
    act.ip_id = f->ip_id++;
    bpf_spin_unlock(&f->lock);
    if (tcp_template_build(ctx, t, cs, &act) < 0) {
        st->build_errors++;
        return XDP_DROP;
    }
    if (resp.flags == TCPF_ACK)
        st->acks_sent++;
    __sync_fetch_and_add(&f->rx_replies, 1);
    return XDP_TX;
}
#endif
