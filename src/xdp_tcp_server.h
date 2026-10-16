#ifndef XDP_TCP_SERVER_H
#define XDP_TCP_SERVER_H

// XDP TCP responder (--tcp-server): the TCP counterpart of the UDP echo
// receiver. xdp_rx_tcp_server is attached to the device and answers every
// segment addressed to the listen port from XDP: SYN -> SYN-ACK, data ->
// ACK (payload discarded), FIN -> FIN+ACK, RST -> drop the flow. It never
// hands an experiment packet to the kernel and never sends data itself.
//
// There is no timer: SYN-ACK and FIN+ACK are retransmitted only when the
// peer retransmits its SYN / FIN (reactive, like dperf's server side). Flow
// state lives in an LRU hash keyed by (peer address, peer port, local
// address); stale
// entries are evicted by the LRU or recycled by a new SYN from the same
// peer. No spin lock: one flow's packets arrive on one RSS queue, so the
// updates are serialized by the NIC in practice. See docs/ja/design_xdp_tcp.md
// section 12.

#include "xdp_tcp.h"

#define TCP_SRV_DEFAULT_MAX_FLOWS 262144

enum tcp_srv_state {
    TS_SYN_RCVD = 1, // SYN-ACK sent, waiting for the third ACK
    TS_ESTABLISHED,
    TS_LAST_ACK, // peer FIN received, our FIN+ACK sent, waiting for its ACK
};

struct tcp_srv_key {
    __u32 addr[4];  // peer address, network byte order; IPv4 in addr[0]
    __u32 local[4]; // our address (the listen address may be a wildcard)
    __u16 port;     // peer port, host byte order
    __u16 pad;
};

struct tcp_srv_flow {
    __u8 state;
    __u8 wscale_ok;     // peer offered window scaling in its SYN
    __u16 unacked_segs; // data segments received since the last ACK we sent
    __u32 iss;          // our ISN
    __u32 snd_nxt;      // next seq we would send (iss+1, +1 after our FIN)
    __u32 rcv_nxt;      // next expected peer seq (= the ack we send)
    __u64 bytes_rcvd;
    __u64 last_ns;
};

struct tcp_srv_cfg {
    __u16 listen_port;
    __u16 vlan_id;
    __u8 vlan_pcp;
    __u8 ip_version; // 4 or 6
    __u8 ack_every;  // ACK every N in-order data segments (>= 1)
    __u8 any_addr;   // 1 = accept any destination address of the family
    __u16 mss;       // advertised in SYN-ACK
    __u16 pad;
    __u32 listen_ip[4]; // network byte order; IPv4 in [0]
};

struct tcp_srv_stats {
    __u64 syn_rcvd;
    __u64 synack_sent;
    __u64 accepted;
    __u64 data_segs;
    __u64 bytes_rcvd;
    __u64 acks_sent;
    __u64 dup_acks_sent; // ACKs sent for duplicate or out-of-order segments
    __u64 out_of_order;
    __u64 fin_rcvd;
    __u64 fin_sent;
    __u64 closed;
    __u64 rst_rcvd;
    __u64 recycled;
    __u64 table_full;
    __u64 stray;      // segments without a flow entry: answered with RST
    __u64 unexpected; // bad ACK number in SYN_RCVD
    __u64 build_errors;
    __u64 rst_sent;
    __u64 reset_est;      // RSTs that removed an established (or closing) flow
    __u64 recycled_est;   // new SYNs that replaced an established (or closing) flow
    __u64 bad_len;        // IP / TCP lengths inconsistent with the frame: dropped
    __u64 challenge_acks; // ACKs sent for a SYN on an established flow or an RST off rcv_nxt (RFC 5961)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TCP_SRV_DEFAULT_MAX_FLOWS); // resized by Go (--tcp-max-conns, 1 in other modes)
    __type(key, struct tcp_srv_key);
    __type(value, struct tcp_srv_flow);
} tcp_srv_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_srv_cfg);
} tcp_srv_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_srv_stats);
} tcp_srv_stats_map SEC(".maps");

SEC("xdp")
int xdp_rx_tcp_server(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct tcp_srv_cfg *cfg = bpf_map_lookup_elem(&tcp_srv_cfg_map, &zero);
    struct tcp_srv_stats *st = bpf_map_lookup_elem(&tcp_srv_stats_map, &zero);
    if (!cfg || !st)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    __u32 l3_off = sizeof(*eth);
    __u8 tagged = 0;
    if (cfg->vlan_id) {
        if (proto == bpf_htons(ETH_P_8021Q)) {
            struct vlan_hdr *vh = data + l3_off;
            if ((void *)(vh + 1) > data_end)
                return XDP_PASS;
            if ((bpf_ntohs(vh->h_vlan_TCI) & 0x0FFF) != cfg->vlan_id)
                return XDP_PASS;
            proto = vh->h_vlan_encapsulated_proto;
            l3_off += sizeof(*vh);
            tagged = 1;
        } else if (proto == bpf_htons(ETH_P_8021AD)) {
            return XDP_PASS;
        }
        // Untagged while a VLAN is configured: tag stripped by the driver or
        // carried in skb metadata; accept on the L3/L4 match, push it back on
        // the reply (same as xdp_rx_tcp).
    } else if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        return XDP_PASS;
    }

    struct tcp_srv_key key = {0};
    __u32 l4_off;
    __u32 payload_len;
    __u32 ip_end; // end of the IP datagram as declared by its header
    if (cfg->ip_version == 4) {
        if (proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;
        struct iphdr *iph = data + l3_off;
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        if (iph->ihl != 5 || iph->protocol != IPPROTO_TCP)
            return XDP_PASS;
        if (!cfg->any_addr && iph->daddr != cfg->listen_ip[0])
            return XDP_PASS;
        // Any fragment, including the first one (MF set, offset 0): no
        // reassembly here, so it is not a complete segment.
        if ((bpf_ntohs(iph->frag_off) & 0x3FFF) != 0)
            return XDP_PASS;
        key.addr[0] = iph->saddr;
        key.local[0] = iph->daddr;
        l4_off = l3_off + sizeof(*iph);
        __u32 tot = bpf_ntohs(iph->tot_len);
        ip_end = l3_off + tot;
        payload_len = tot >= sizeof(*iph) ? tot - sizeof(*iph) : 0;
    } else {
        if (proto != bpf_htons(ETH_P_IPV6))
            return XDP_PASS;
        struct ipv6hdr *ip6h = data + l3_off;
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        if (ip6h->nexthdr != IPPROTO_TCP)
            return XDP_PASS;
        if (!cfg->any_addr &&
            (ip6h->daddr.in6_u.u6_addr32[0] != cfg->listen_ip[0] || ip6h->daddr.in6_u.u6_addr32[1] != cfg->listen_ip[1] ||
             ip6h->daddr.in6_u.u6_addr32[2] != cfg->listen_ip[2] || ip6h->daddr.in6_u.u6_addr32[3] != cfg->listen_ip[3]))
            return XDP_PASS;
        key.addr[0] = ip6h->saddr.in6_u.u6_addr32[0];
        key.addr[1] = ip6h->saddr.in6_u.u6_addr32[1];
        key.addr[2] = ip6h->saddr.in6_u.u6_addr32[2];
        key.addr[3] = ip6h->saddr.in6_u.u6_addr32[3];
        key.local[0] = ip6h->daddr.in6_u.u6_addr32[0];
        key.local[1] = ip6h->daddr.in6_u.u6_addr32[1];
        key.local[2] = ip6h->daddr.in6_u.u6_addr32[2];
        key.local[3] = ip6h->daddr.in6_u.u6_addr32[3];
        l4_off = l3_off + sizeof(*ip6h);
        payload_len = bpf_ntohs(ip6h->payload_len);
        ip_end = l4_off + payload_len;
    }

    struct tcphdr *th = data + l4_off;
    if ((void *)(th + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(th->dest) != cfg->listen_port)
        return XDP_PASS;
    key.port = bpf_ntohs(th->source);

    // From here on the packet is ours: never XDP_PASS (the kernel has no
    // socket on this port and would answer with RST).
    __u32 seq = bpf_ntohl(th->seq);
    __u32 ack = bpf_ntohl(th->ack_seq);
    __u8 flags = ((__u8 *)th)[13];
    __u32 doff = th->doff;
    __u32 hl = doff * 4;
    // The declared lengths must fit in the frame (trailing Ethernet padding
    // is fine) and leave room for the TCP header; otherwise the segment
    // would be acked for bytes that never arrived.
    if (hl < TCP_HDR_LEN || payload_len < hl || ip_end > (__u32)(data_end - data)) {
        st->bad_len++;
        return XDP_DROP;
    }
    payload_len -= hl;

    __u64 now = bpf_ktime_get_ns();
    struct tcp_srv_flow *f = bpf_map_lookup_elem(&tcp_srv_flow_map, &key);
    struct tcp_reply r = {0};

    if (flags & TCPF_RST) {
        st->rst_rcvd++;
        if (!f)
            return XDP_DROP;
        // RFC 5961 3.2: only an RST at exactly rcv_nxt removes the flow. A
        // stale RST (an earlier connection on this 4-tuple) or a spoofed one
        // gets a challenge ACK on a synchronized flow (a genuine peer answers
        // with an RST at the right seq) and is ignored in SYN_RCVD.
        if (seq == f->rcv_nxt) {
            if (f->state != TS_SYN_RCVD)
                st->reset_est++;
            bpf_map_delete_elem(&tcp_srv_flow_map, &key);
            return XDP_DROP;
        }
        if (f->state == TS_SYN_RCVD)
            return XDP_DROP;
        r.seq = f->snd_nxt;
        r.ack = f->rcv_nxt;
        r.flags = TCPF_ACK;
        st->challenge_acks++;
        goto send;
    }

    if ((flags & (TCPF_SYN | TCPF_ACK)) == TCPF_SYN) {
        st->syn_rcvd++;
        if (f && f->state == TS_ESTABLISHED) {
            // RFC 5961 4.2: a SYN on an established flow is either a delayed
            // duplicate (replacing the flow would break a live transfer) or
            // a peer that restarted on the same port. Answer with a challenge
            // ACK: a restarted peer resets the old flow with an RST at
            // rcv_nxt and retries its SYN; a duplicate is harmless.
            r.seq = f->snd_nxt;
            r.ack = f->rcv_nxt;
            r.flags = TCPF_ACK;
            st->challenge_acks++;
            goto send;
        }
        struct tcp_srv_flow nf = {0};
        if (f && f->state == TS_SYN_RCVD && f->rcv_nxt == seq + 1) {
            // Same SYN again: our SYN-ACK was lost, resend the same one. The
            // entry is alive: refresh its age for the control-plane sweeper.
            f->last_ns = now;
            nf = *f;
        } else {
            if (f) {
                // fast recycle of a stale entry (no TIME_WAIT): a SYN_RCVD
                // flow with another ISN, or a LAST_ACK flow (the peer is done)
                st->recycled++;
                if (f->state != TS_SYN_RCVD)
                    st->recycled_est++;
            }
            __u8 ws = 0xFF;
            __u16 peer_mss = 0;
            if (doff > 5)
                tcp_parse_syn_opts(ctx, l4_off, doff, &ws, &peer_mss);
            nf.state = TS_SYN_RCVD;
            nf.wscale_ok = (ws != 0xFF);
            nf.iss = bpf_get_prandom_u32();
            nf.snd_nxt = nf.iss + 1;
            nf.rcv_nxt = seq + 1;
            nf.last_ns = now;
            if (bpf_map_update_elem(&tcp_srv_flow_map, &key, &nf, BPF_ANY) < 0) {
                st->table_full++;
                return XDP_DROP;
            }
        }
        r.seq = nf.iss;
        r.ack = nf.rcv_nxt;
        r.flags = TCPF_SYN | TCPF_ACK;
        r.opt_len = TCP_SYN_OPT_LEN;
        r.mss = cfg->mss;
        r.wscale = nf.wscale_ok ? 7 : 0xFF;
        st->synack_sent++;
        goto send;
    }

    if (!f) {
        // No state for this peer (never seen, swept, or evicted by the LRU).
        // Reset it so a Linux client fails fast instead of hanging (RFC 9293
        // 3.10.7.1): <SEQ=SEG.ACK><CTL=RST> if the segment has an ACK, else
        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
        st->stray++;
        if (flags & TCPF_ACK) {
            r.seq = ack;
            r.flags = TCPF_RST;
        } else {
            r.seq = 0;
            r.ack = seq + payload_len + ((flags & TCPF_FIN) ? 1 : 0);
            r.flags = TCPF_RST | TCPF_ACK;
        }
        st->rst_sent++;
        goto send;
    }
    if (!(flags & TCPF_ACK)) {
        st->unexpected++;
        return XDP_DROP;
    }

    __u8 state = f->state;
    if (state == TS_SYN_RCVD) {
        // The ACK number proves the peer saw our SYN-ACK; the segment's seq
        // may already be ahead when the handshake ACK and the first data
        // were lost (burst drops), so it is handled as data below (and
        // answered with a duplicate ACK that triggers fast retransmit).
        if (ack != f->snd_nxt) {
            // Not an ACK of our SYN-ACK (RFC 9293 SYN-RECEIVED): reset.
            st->unexpected++;
            r.seq = ack;
            r.flags = TCPF_RST;
            st->rst_sent++;
            goto send;
        }
        f->state = TS_ESTABLISHED;
        state = TS_ESTABLISHED;
        st->accepted++;
    }
    if (seq_after(ack, f->snd_nxt)) {
        // Acks something we never sent (RFC 9293 3.10.7.4): answer with our
        // current ACK and drop the segment, data and FIN included.
        st->unexpected++;
        r.seq = f->snd_nxt;
        r.ack = f->rcv_nxt;
        r.flags = TCPF_ACK;
        st->acks_sent++;
        goto send;
    }
    f->last_ns = now;

    __u8 need_ack = 0;
    __u8 fin_in_order = 0;
    __u32 rcv_nxt = f->rcv_nxt;
    if (payload_len > 0) {
        __u32 end = seq + payload_len;
        if (!seq_after(seq, rcv_nxt) && seq_after(end, rcv_nxt)) {
            // Starts at or before rcv_nxt and carries new bytes. A
            // retransmission may be repacketized, so only the part beyond
            // rcv_nxt is new (RFC 9293 3.10.7.4 trimming).
            if (state == TS_ESTABLISHED) {
                __u32 n = end - rcv_nxt;
                __u8 trimmed = (seq != rcv_nxt);
                f->rcv_nxt = end;
                rcv_nxt = end;
                f->bytes_rcvd += n;
                st->bytes_rcvd += n;
                st->data_segs++;
                f->unacked_segs++;
                if (f->unacked_segs >= cfg->ack_every || (flags & (TCPF_PSH | TCPF_FIN)) || trimmed)
                    need_ack = 1;
            } else {
                need_ack = 1; // data after the peer's FIN: just ack
            }
            fin_in_order = 1;
        } else if (!seq_after(end, rcv_nxt)) {
            // Duplicate / already received: ack what we have. A FIN right
            // after the duplicate data is still in order.
            need_ack = 1;
            st->dup_acks_sent++;
            fin_in_order = (end == rcv_nxt);
        } else {
            // Hole before this segment: duplicate ACK triggers the peer's
            // fast retransmit. The segment (and any FIN on it) is discarded.
            st->out_of_order++;
            st->dup_acks_sent++;
            need_ack = 1;
        }
    } else if (seq == rcv_nxt) {
        fin_in_order = 1;
    } else {
        // Empty segment out of sequence: a keepalive probe (seq =
        // rcv_nxt - 1) or a FIN ahead of missing data. Answer with the
        // current rcv_nxt (RFC 9293 3.10.7.4).
        need_ack = 1;
    }

    if (flags & TCPF_FIN) {
        if (state == TS_ESTABLISHED && fin_in_order) {
            f->rcv_nxt += 1;
            f->state = TS_LAST_ACK;
            f->unacked_segs = 0;
            st->fin_rcvd++;
            r.seq = f->snd_nxt;
            f->snd_nxt += 1;
            r.ack = f->rcv_nxt;
            r.flags = TCPF_FIN | TCPF_ACK;
            st->fin_sent++;
            goto send;
        }
        if (state == TS_LAST_ACK) {
            // The peer retransmitted its FIN: our FIN+ACK was lost.
            r.seq = f->snd_nxt - 1;
            r.ack = f->rcv_nxt;
            r.flags = TCPF_FIN | TCPF_ACK;
            st->fin_sent++;
            goto send;
        }
    }

    if (state == TS_LAST_ACK) {
        if (ack == f->snd_nxt) {
            bpf_map_delete_elem(&tcp_srv_flow_map, &key);
            st->closed++;
            return XDP_DROP;
        }
        if (ack == f->snd_nxt - 1 && !need_ack) {
            // The peer acks everything but our FIN: our FIN+ACK was lost and
            // the peer (FIN_WAIT_2) probes with an ACK. Resend it.
            r.seq = f->snd_nxt - 1;
            r.ack = f->rcv_nxt;
            r.flags = TCPF_FIN | TCPF_ACK;
            st->fin_sent++;
            goto send;
        }
    }

    if (!need_ack)
        return XDP_DROP;
    f->unacked_segs = 0;
    r.seq = f->snd_nxt;
    r.ack = f->rcv_nxt;
    r.flags = TCPF_ACK;
    st->acks_sent++;

send:
    if (tcp_reply_inplace(ctx, l3_off, cfg->ip_version, cfg->vlan_id && !tagged, cfg->vlan_id, cfg->vlan_pcp, &r) < 0) {
        st->build_errors++;
        return XDP_DROP;
    }
    return XDP_TX;
}

#endif // XDP_TCP_SERVER_H
