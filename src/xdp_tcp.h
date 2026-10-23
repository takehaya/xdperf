#include "xdp_mixed.h"
#ifndef XDP_TCP_H
#define XDP_TCP_H

// XDP TCP stream mode: a minimal TCP client (SYN / data / FIN, go-back-N
// retransmission, fixed window) implemented entirely in XDP.
//
//   xdp_tx_tcp_mixed runs under BPF_PROG_RUN live frames; every invocation picks one
//               flow owned by the current CPU and emits SYN / data / FIN /
//               retransmission for it, or returns XDP_DROP when nothing to send.
//   xdp_rx_tcp_mixed is reached from the attached xdp_rx_mixed; it consumes every packet that
//               belongs to an experiment flow (XDP_TX an ACK or XDP_DROP) and
//               passes everything else untouched (XDP_PASS).
//
// Flow state lives in tcp_flow_map (ARRAY) and is serialized between the TX
// worker and the RX NAPI context with bpf_spin_lock. No timers: RTO is checked
// by the TX loop from bpf_ktime_get_ns(). The payload is all-zero so the TCP
// checksum only covers the pseudo header + TCP header (O(1) per segment).
// See docs/ja/design_xdp_tcp.md.

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_prog.h"
#include "xdp_utils.h"

#define MAX_TCP_FLOWS 65536
#define TCP_TX_SCAN 8 // flows examined per TX iteration before giving up
#define TCP_HDR_LEN 20
#define TCP_SYN_OPT_LEN 8 // MSS(4) + NOP(1) + WS(3)
#define TCP_MAX_L4_OFF 58 // 14 + 4 (VLAN) + 40 (IPv6)

#define TCPF_FIN 0x01
#define TCPF_SYN 0x02
#define TCPF_RST 0x04
#define TCPF_PSH 0x08
#define TCPF_ACK 0x10

enum tcp_flow_state {
    TF_CLOSED = 0, // SYN not sent yet
    TF_SYN_SENT,
    TF_ESTABLISHED,
    TF_FIN_WAIT_1, // our FIN sent, waiting for its ACK
    TF_FIN_WAIT_2, // our FIN acked, waiting for the peer's FIN
    TF_DONE,       // peer FIN acked: clean close
    TF_FAILED,     // RST received/sent, or a retry limit exceeded
    TF_SKIPPED,    // never opened: drain/abort started before its SYN
};

struct tcp_flow {
    struct bpf_spin_lock lock;
    __u8 state;
    __u8 syn_retries;
    __u8 fin_retries; // FIN retransmissions (FIN_WAIT_1) or ACK probes (FIN_WAIT_2)
    __u8 dup_acks;
    __u8 rtx_pending; // RX saw 3 dup ACKs -> TX resends the oldest segment
    __u8 peer_fin;    // peer FIN received
    __u8 wscale;      // window scale offered by the peer in SYN-ACK
    __u8 rtx_retries; // consecutive RTOs without ACK progress (backoff + give-up)
    __u16 src_port;   // host byte order
    __u16 mss;        // effective MSS: min(cfg mss, peer MSS); set on SYN-ACK
    __u8 syn_rst;     // SYN_SENT: bit0 = RST sent to a stale peer, resend SYN now; bit1 = used
    __u8 ts_enabled;
    __u8 started; // first successfully built SYN, written only by the owner TX worker
    __u8 _started_pad;
    __u16 ip_id;       // IPv4 ID of the next frame (per connection, like Linux)
    __u32 iss;         // our initial sequence number
    __u32 snd_una;     // oldest unacknowledged seq
    __u32 snd_nxt;     // next seq to send (rewound to snd_una + 1 segment on RTO)
    __u32 snd_max;     // highest seq ever sent (+ len); ACKs up to here are valid
    __u32 rcv_nxt;     // next expected peer seq (= our ack number)
    __u32 snd_wnd;     // peer receive window in bytes (scale applied)
    __u32 template_id; // mixed group, occupies existing alignment padding
    __u32 ts_recent;
    __u32 ts_clock;
    __u64 ts_recent_ns;
    __u64 bytes_target; // bytes to send on this flow (0 = unlimited, until drain)
    __u64 bytes_acked;  // payload bytes acked (64-bit: never derived from 32-bit seq numbers)
    __u64 last_send_ns; // last (re)transmission, for RTO
    __u64 last_ack_ns;
    // Per-flow ledger, read by Go for --tcp-flow-report. Counted with atomic
    // adds after the frame is built, so a frame that failed to build is not
    // counted (it shows up in tcp_stats.build_errors instead).
    __u64 tx_pkts;    // frames TCP TX sent: SYN, data, FIN, retransmissions, probes, RST
    __u64 tx_data;    // new data segments (first transmission)
    __u64 tx_rtx;     // retransmitted data segments (RTO, dup ACK, go-back-N)
    __u64 rx_replies; // ACK / RST frames TCP RX bounced back for this flow
    __u64 rx_pkts;    // frames received from the peer for this flow
};

struct tcp_cfg {
    __u32 flow_count;  // retained connection states, including old DONE entries
    __u32 slot_count;  // nonzero only in connection repetition mode
    __u32 window_segs; // max segments in flight per flow
    __u16 mss;         // payload bytes per segment
    __u16 port_base;   // src port = port_base + flow_idx (host order)
    __u16 dst_port;    // host order
    __u16 hdr_len;     // Eth(+VLAN) + IP + TCP(20)
    __u16 l3_off;      // 14, or 18 with a VLAN tag
    __u16 l4_off;      // l3_off + 20 (IPv4) / 40 (IPv6)
    __u16 vlan_id;     // 0 = untagged
    __u8 ip_version;   // 4 or 6
    __u8 max_syn_retries;
    __u8 max_fin_retries;
    __u8 drain;            // 1 = stop new data, close every flow (Go sets it on --duration / signal)
    __u8 vlan_pcp;         // 802.1Q priority for tags pushed by TCP RX
    __u8 abort;            // 1 = reset every open flow with RST and stop (Go: drain timeout / 2nd signal)
    __u8 max_data_retries; // consecutive RTOs before a flow gives up with RST
    __u8 ip_id_shared;     // 1 = one IPv4 ID counter per TX CPU (interleaved flows defeat GRO)
    __u8 _pad[2];
    // Go rewrites the whole struct to flip drain/abort while TX/RX run; every
    // other field keeps its value, so a torn read is harmless.
    __u32 pseudo_sum; // 16-bit word sum of src+dst address (pseudo header), unfolded
    __u32 src_ip[4];  // network order; IPv4 uses the first word
    __u32 dst_ip[4];
    __u64 bytes_per_flow;
    __u64 rto_ns;
    // Ethernet(+VLAN)+IP header template (first l4_off bytes of the frame).
    // Rewritten into every frame: live frames are recycled zero-copy, and a
    // receiver on the same host (veth) may modify the header area in place
    // (e.g. skb_vlan_untag's memmove), so nothing in the frame can be trusted.
    __u8 hdr_tmpl[64];
};

struct tcp_length_patch {
    __u16 offset;
    __u16 constant;
};
struct tcp_outer_ip {
    __u16 offset;
    __u8 version;
    __u8 _pad;
};
struct tcp_outer_udp {
    __u16 offset;
    __u16 ip_offset;
    __u32 pseudo_sum;
    __u8 version;
    __u8 mode;
    __u16 _pad;
};
struct tcp_template {
    struct tcp_cfg cfg;
    __u8 prefix[256];
    struct tcp_length_patch lengths[8];
    struct tcp_outer_ip outer_ips[4];
    struct tcp_outer_udp udps[4];
    __u16 entropy_offset;
    __u16 entropy_base;
    __u16 entropy_count;
    __u8 length_count;
    __u8 outer_ip_count;
    __u8 udp_count;
    __u8 tcp_header[20];
    __u32 syn_sum;
    __u32 data_sum;
    __u8 syn_options[40];
    __u8 data_options[40];
    __u8 syn_len;
    __u8 data_len;
    __u8 timestamps;
    __u8 payload_id;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct tcp_template);
} tcp_template_map SEC(".maps");

// Patterns are shared by group, including expanded per-flow templates.
struct tcp_payload {
    __u32 sums[257]; // sums of network-order 16-bit words over an even period
    __u8 bytes[512];
    __u16 period;
    __u16 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct tcp_payload);
} tcp_payload_map SEC(".maps");
const volatile __u32 mixed_has_timestamps SEC(".rodata.mixed") = 0;
const volatile __u32 mixed_has_payload SEC(".rodata.mixed") = 0;

// Per-CPU TX state. Flow ownership: this CPU drives flows first, first+stride, ...
struct tcp_cpu_state {
    __u32 first;
    __u32 stride;
    __u32 count;
    __u32 cursor;
    __u32 ip_id;
};

struct tcp_stats {
    __u64 started;
    __u64 syn_sent;
    __u64 synack_rcvd;
    __u64 established;
    __u64 data_segs;
    __u64 data_bytes;
    __u64 bytes_acked;
    __u64 rtx_segs;
    __u64 rtx_timeouts;
    __u64 rtx_dupack;
    __u64 fin_sent;
    __u64 done;
    __u64 failed;
    __u64 rst_rcvd;
    __u64 acks_rcvd;
    __u64 acks_sent;
    __u64 idle_iters;
    __u64 window_stalls;
    __u64 unexpected;
    __u64 build_errors;
    __u64 rst_sent;           // RSTs we sent (stale peer, abort, give-up)
    __u64 failed_est;         // flows that failed after being established
    __u64 skipped;            // flows never opened (drain/abort before SYN)
    __u64 aborted;            // flows reset by abort
    __u64 rtx_giveups;        // flows reset after max_data_retries RTOs
    __u64 fin_wait2_timeouts; // flows reset waiting for the peer FIN
    __u64 ack_probes;         // pure ACKs sent from FIN_WAIT_2 to elicit a lost FIN
    __u64 window_probes;      // probes sent while the peer window is closed (persist)
    __u64 challenge_acks;     // ACKs sent for an RST whose seq is not rcv_nxt (RFC 5961)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TCP_FLOWS);
    __type(key, __u32);
    __type(value, struct tcp_flow);
} tcp_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_cfg);
} tcp_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_cpu_state);
} tcp_cpu_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_stats);
} tcp_stats_map SEC(".maps");

// Only the owner TX worker advances a slot; connection states are never reused.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TCP_FLOWS);
    __type(key, __u32);
    __type(value, __u32);
} tcp_slot_map SEC(".maps");

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static __always_inline int seq_after(__u32 a, __u32 b)
{
    return (__s32)(a - b) > 0;
}

// a <= b in sequence space
static __always_inline int seq_leq(__u32 a, __u32 b)
{
    return !seq_after(a, b);
}

static __always_inline __u16 tcp_csum_fold(__u64 sum)
{
    sum = (sum & 0xFFFFFFFF) + (sum >> 32);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

static __always_inline void put_be16(__u8 *p, __u16 v)
{
    p[0] = v >> 8;
    p[1] = v & 0xFF;
}

static __always_inline void put_be32(__u8 *p, __u32 v)
{
    p[0] = v >> 24;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

// Sum of n 16-bit words from a stack buffer; n must be a compile-time constant.
#define SUM16_BUF(sum, buf, nbytes)                                                                                                \
    do {                                                                                                                           \
        _Pragma("unroll") for (int _i = 0; _i < (nbytes); _i += 2)                                                                 \
        {                                                                                                                          \
            (sum) += ((__u32)(buf)[_i] << 8) | (buf)[_i + 1];                                                                      \
        }                                                                                                                          \
    } while (0)

// ---------------------------------------------------------------------------
// TX: decide what to send for one flow (runs under the flow lock)
// ---------------------------------------------------------------------------

enum tcp_tx_kind {
    TXA_NONE = 0,
    TXA_SYN,
    TXA_DATA,
    TXA_FIN,
    TXA_RTX_TO,     // first segment resent after an RTO (go-back-N restarts here)
    TXA_RTX_DUPACK, // oldest segment resent after 3 dup ACKs
    TXA_RTX_GBN,    // rest of the go-back-N region (snd_nxt < snd_max)
    TXA_ACK,        // pure ACK probe from FIN_WAIT_2
    TXA_RST,        // abort / give-up
    TXA_CLOSED,     // state changed, nothing to send (keep scanning)
    TXA_WND_PROBE,  // pure ACK below snd_una while the peer window is closed
};

struct tcp_tx_action {
    __u32 seq;
    __u32 ack;
    __u32 len;
    __u16 src_port;
    __u8 flags;
    __u8 kind;
    __u16 ip_id;
};

// Optional state never enlarges the legacy action or its stack frame.
struct tcp_tx_extra {
    __u8 timestamps;
    __u16 ip_id;
    __u32 tsval;
    __u32 tsecr;
    __u64 stream_offset;
};

// Keep closure bookkeeping off the RX parser stack on older kernels.
static __noinline void mixed_count_closed(struct tcp_flow *f)
{
    __u32 zero = 0;
    struct mixed_cfg *cfg = bpf_map_lookup_elem(&mixed_cfg_map, &zero);
    struct tcp_cfg *tcp = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
    if (!cfg || !tcp || !cfg->workers || tcp->slot_count)
        return;
    __u32 slot = (__u32)(f->src_port - tcp->port_base) % cfg->workers;
    __u32 *closed = bpf_map_lookup_elem(&mixed_closed_map, &slot);
    if (closed)
        __sync_fetch_and_add(closed, 1);
}
static __always_inline int mixed_flow_closed(__u8 state)
{
    return state == TF_DONE || state == TF_FAILED || state == TF_SKIPPED;
}

// A slot is retired once; RX closure counts remain disabled in repetition mode.
static __noinline struct tcp_flow *tcp_slot_flow(__u32 slot, const struct tcp_cfg *cfg)
{
    __u32 *current = bpf_map_lookup_elem(&tcp_slot_map, &slot);
    if (!current || *current >= cfg->flow_count)
        return NULL;
    __u32 idx = *current;
    struct tcp_flow *f = bpf_map_lookup_elem(&tcp_flow_map, &idx);
    if (!f || !mixed_flow_closed(f->state))
        return f;
    __u32 next = idx + cfg->slot_count;
    if (!cfg->drain && !cfg->abort && next < cfg->flow_count) {
        *current = next;
        return bpf_map_lookup_elem(&tcp_flow_map, &next);
    }
    *current = 0xffffffff;
    struct mixed_cfg *mix = bpf_map_lookup_elem(&mixed_cfg_map, &(__u32){0});
    if (mix && mix->workers) {
        __u32 owner = slot % mix->workers;
        __u32 *closed = bpf_map_lookup_elem(&mixed_closed_map, &owner);
        if (closed)
            __sync_fetch_and_add(closed, 1);
    }
    return NULL;
}

static __always_inline int tcp_flow_open(__u8 state)
{
    return state == TF_ESTABLISHED || state == TF_FIN_WAIT_1 || state == TF_FIN_WAIT_2;
}

// Give up on a flow with a RST (caller holds the lock). seq = snd_max: the
// peer's RCV.NXT is somewhere in [snd_una, snd_max]; if it is lower, Linux
// answers with a challenge ACK and TCP RX replies RST at SEG.ACK, which is
// exact (RFC 5961).
static __always_inline int tcp_tx_fail(struct tcp_flow *f, struct tcp_stats *st, struct tcp_tx_action *a)
{
    __u8 was_open = tcp_flow_open(f->state);
    a->seq = f->snd_max;
    a->ack = was_open ? f->rcv_nxt : 0;
    a->flags = was_open ? (TCPF_RST | TCPF_ACK) : TCPF_RST;
    a->len = 0;
    f->state = TF_FAILED;
    st->failed++;
    if (was_open)
        st->failed_est++;
    return TXA_RST;
}

// Returns the action kind; fills *a. No helper calls inside the lock region.
static __always_inline int tcp_tx_decide(struct tcp_flow *f, const struct tcp_cfg *cfg, struct tcp_stats *st, __u64 now,
                                         struct tcp_tx_action *a, struct tcp_tx_extra *extra, const int mixed_mode,
                                         const int timestamps, const int track_closed)
{
    int kind = TXA_NONE;
    __u64 rto = cfg->rto_ns;
    // Scheduling and TCP decisions share one stop flag, even during template updates.
    __u32 zero = 0;
    struct tcp_cfg *global = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
    if (!global)
        return TXA_NONE;
    __u8 drain = global->drain;
    __u8 abort = global->abort;

    bpf_spin_lock(&f->lock);
    a->src_port = f->src_port;
    __u8 state = f->state;

    if (state == TF_CLOSED) {
        if (drain || abort) {
            f->state = TF_SKIPPED;
            st->skipped++;
            kind = TXA_CLOSED;
        } else {
            f->state = TF_SYN_SENT;
            f->snd_una = f->iss;
            f->snd_nxt = f->iss + 1;
            f->snd_max = f->iss + 1;
            f->last_send_ns = now;
            a->seq = f->iss;
            a->ack = 0;
            a->flags = TCPF_SYN;
            a->len = 0;
            kind = TXA_SYN;
        }
        goto out;
    }
    if (abort && (state == TF_SYN_SENT || tcp_flow_open(state))) {
        kind = tcp_tx_fail(f, st, a);
        st->aborted++;
        goto out;
    }

    switch (state) {
    case TF_SYN_SENT:
        if (f->syn_rst & 1) {
            // TCP RX just reset a stale peer connection on this port:
            // retry once right away, then fall back to the normal backoff
            // (so a peer that keeps answering with challenge ACKs cannot make
            // us loop without consuming retries).
            f->syn_rst = 2;
            f->last_send_ns = now;
            a->seq = f->iss;
            a->ack = 0;
            a->flags = TCPF_SYN;
            a->len = 0;
            kind = TXA_SYN;
        } else if (now - f->last_send_ns > (rto << f->syn_retries)) {
            if (f->syn_retries >= cfg->max_syn_retries) {
                f->state = TF_FAILED;
                st->failed++;
                kind = TXA_CLOSED;
            } else {
                f->syn_retries++;
                f->last_send_ns = now;
                a->seq = f->iss;
                a->ack = 0;
                a->flags = TCPF_SYN;
                a->len = 0;
                kind = TXA_SYN;
            }
        }
        break;

    case TF_ESTABLISHED: {
        __u32 mss = f->mss ? f->mss : cfg->mss;
        __u32 in_flight = f->snd_nxt - f->snd_una;
        __u32 outstanding = f->snd_max - f->snd_una;
        __u64 remaining = ~0ULL; // payload bytes not yet acked (from snd_una)
        if (f->bytes_target)
            remaining = f->bytes_target > f->bytes_acked ? f->bytes_target - f->bytes_acked : 0;

        if (outstanding && f->rtx_pending) {
            // fast retransmit: resend the oldest unacked segment only and
            // keep snd_nxt (the later in-flight segments are probably fine)
            __u32 len = mss < outstanding ? mss : outstanding;
            kind = TXA_RTX_DUPACK;
            f->rtx_pending = 0;
            f->dup_acks = 0;
            f->last_send_ns = now;
            a->seq = f->snd_una;
            a->ack = f->rcv_nxt;
            a->flags = TCPF_ACK | TCPF_PSH;
            a->len = len;
            break;
        }
        __u8 shift = f->rtx_retries < 6 ? f->rtx_retries : 6;
        if (outstanding && now - f->last_send_ns > (rto << shift)) {
            if (f->rtx_retries >= cfg->max_data_retries) {
                kind = tcp_tx_fail(f, st, a);
                st->rtx_giveups++;
                break;
            }
            // RTO: go-back-N from snd_una (snd_max is kept, so ACKs for data
            // the peer had buffered are still accepted), exponential backoff
            __u32 len = mss < outstanding ? mss : outstanding;
            kind = TXA_RTX_TO;
            f->rtx_retries++;
            f->rtx_pending = 0;
            f->dup_acks = 0;
            f->snd_nxt = f->snd_una + len;
            f->last_send_ns = now;
            a->seq = f->snd_una;
            a->ack = f->rcv_nxt;
            a->flags = TCPF_ACK | TCPF_PSH;
            a->len = len;
            break;
        }

        // Next segment at snd_nxt: either the rest of a go-back-N region
        // (allowed even while draining, otherwise the flow could never reach
        // FIN) or new data.
        __u64 avail = 0;
        __u8 rexmit = 0;
        if (seq_after(f->snd_max, f->snd_nxt)) {
            avail = f->snd_max - f->snd_nxt;
            rexmit = 1;
        } else if (!drain && remaining > (__u64)in_flight) {
            avail = remaining - in_flight;
        }
        if (avail > 0) {
            __u32 wnd = cfg->window_segs * mss;
            if (wnd > f->snd_wnd)
                wnd = f->snd_wnd;
            __u32 len = mss;
            if ((__u64)len > avail)
                len = (__u32)avail;
            // A peer window smaller than one segment (a slow receiver): with
            // nothing in flight, send what fits instead of waiting for a
            // window that may never reach a full segment. Only then, so a
            // partly filled window does not turn into small segments.
            if (in_flight == 0 && wnd > 0 && len > wnd)
                len = wnd;
            if (in_flight + len <= wnd) {
                // PSH on the last segment and whenever the next one would not
                // fit the window: a responder that acks every N segments
                // (--tcp-ack-every) then acks at least once per window.
                __u8 push = ((__u64)len >= avail) || (in_flight + len + mss > wnd);
                a->seq = f->snd_nxt;
                a->ack = f->rcv_nxt;
                a->flags = TCPF_ACK | (push ? TCPF_PSH : 0);
                a->len = len;
                f->snd_nxt += len;
                if (seq_after(f->snd_nxt, f->snd_max))
                    f->snd_max = f->snd_nxt;
                f->last_send_ns = now;
                kind = rexmit ? TXA_RTX_GBN : TXA_DATA;
            } else {
                st->window_stalls++;
                // Window closed with nothing in flight: no ACK will come by
                // itself, and a lost window update would stall the flow
                // forever. Persist: every RTO send a pure ACK with an old seq,
                // which the peer must answer with its current window
                // (RFC 9293 3.8.6.1). Never gives up, like a persist timer.
                if (outstanding == 0 && now - f->last_send_ns > rto) {
                    a->seq = f->snd_una - 1;
                    a->ack = f->rcv_nxt;
                    a->flags = TCPF_ACK;
                    a->len = 0;
                    f->last_send_ns = now;
                    kind = TXA_WND_PROBE;
                }
            }
        } else if (outstanding == 0) {
            a->seq = f->snd_nxt;
            a->ack = f->rcv_nxt;
            a->flags = TCPF_FIN | TCPF_ACK;
            a->len = 0;
            f->snd_nxt += 1;
            f->snd_max = f->snd_nxt;
            f->state = TF_FIN_WAIT_1;
            f->fin_retries = 0;
            f->last_send_ns = now;
            kind = TXA_FIN;
        }
        break;
    }

    case TF_FIN_WAIT_1:
        if (now - f->last_send_ns > (rto << f->fin_retries)) {
            if (f->fin_retries >= cfg->max_fin_retries) {
                kind = tcp_tx_fail(f, st, a);
            } else {
                f->fin_retries++;
                f->last_send_ns = now;
                a->seq = f->snd_max - 1;
                a->ack = f->rcv_nxt;
                a->flags = TCPF_FIN | TCPF_ACK;
                a->len = 0;
                kind = TXA_FIN;
            }
        }
        break;

    case TF_FIN_WAIT_2:
        // Our FIN is acked, the peer's FIN has not arrived. A reactive peer
        // (--tcp-server) whose FIN+ACK was lost resends it when it sees an
        // ACK that does not cover its FIN, so probe with pure ACKs.
        if (now - f->last_send_ns > (rto << f->fin_retries)) {
            if (f->fin_retries >= cfg->max_fin_retries) {
                kind = tcp_tx_fail(f, st, a);
                st->fin_wait2_timeouts++;
            } else {
                f->fin_retries++;
                f->last_send_ns = now;
                a->seq = f->snd_max;
                a->ack = f->rcv_nxt;
                a->flags = TCPF_ACK;
                a->len = 0;
                kind = TXA_ACK;
            }
        }
        break;

    default:
        break;
    }
out:
    if (kind != TXA_NONE && kind != TXA_CLOSED)
        a->ip_id = f->ip_id++;
    if (mixed_mode && mixed_has_payload && a->len)
        extra->stream_offset = f->bytes_acked + (__u32)(a->seq - f->snd_una);
    if (mixed_mode && mixed_has_timestamps && timestamps) {
        __u32 clock = now / 1000000;
        if (state != TF_CLOSED && (__s32)(clock - f->ts_clock) < 0)
            clock = f->ts_clock;
        f->ts_clock = clock;
        extra->timestamps = (a->flags & TCPF_SYN) || f->ts_enabled;
        extra->tsval = clock;
        extra->tsecr = (a->flags & TCPF_ACK) ? f->ts_recent : 0;
    }
    int closed = track_closed && !mixed_flow_closed(state) && mixed_flow_closed(f->state);
    bpf_spin_unlock(&f->lock);
    if (closed)
        mixed_count_closed(f);
    a->kind = kind;
    return kind;
}

#include "xdp_tcp_template.h"
#include "xdp_tcp_template_ext.h"

// Keep the mixed decision stack separate from the extended frame builder.
struct tcp_mixed_decision {
    struct tcp_tx_action act;
    struct tcp_tx_extra extra;
    __u64 now;
};

static __noinline int tcp_tx_decide_mixed(struct tcp_flow *f, const struct tcp_template *tmpl, struct tcp_stats *st,
                                          struct tcp_mixed_decision *decision, int extended)
{
    // Drain may scan templates with different timestamp settings.
    if (extended && mixed_has_timestamps)
        decision->extra.timestamps = 0;
    return tcp_tx_decide(f, &tmpl->cfg, st, decision->now, &decision->act, &decision->extra, extended,
                         extended && mixed_has_timestamps && tmpl->timestamps, 1);
}

// Compile separate entry points for basic and extended TCP templates.
static __always_inline int tcp_tx_run(struct xdp_md *ctx, const int extended)
{
    __u32 zero = 0;
    struct tcp_cfg *cfg = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
    struct tcp_cpu_state *cs = bpf_map_lookup_elem(&tcp_cpu_state_map, &zero);
    struct tcp_stats *st = bpf_map_lookup_elem(&tcp_stats_map, &zero);
    if (!cfg || !cs || !st)
        return XDP_ABORTED;
    struct mixed_state *mixed = bpf_map_lookup_elem(&mixed_state_map, &zero);
    if (!mixed)
        return XDP_ABORTED;
    if (cs->count == 0) {
        st->idle_iters++;
        return XDP_DROP;
    }

    __u32 first = cs->first, count = cs->count;
    __u32 *next = &cs->cursor;
    if (mixed->selected_group != 0xffffffff) {
        __u32 key = mixed->selected_group;
        struct mixed_group *group = bpf_map_lookup_elem(&mixed_group_map, &key);
        if (!group)
            return XDP_ABORTED;
        first = group->first;
        count = group->count;
        next = &group->cursor;
        if (!count) {
            st->idle_iters++;
            return XDP_DROP;
        }
    }

    const struct tcp_cfg *global = cfg;
    struct tcp_mixed_decision decision = {.now = bpf_ktime_get_ns()};
    struct tcp_flow *sel = NULL;
    int kind = TXA_NONE;
    struct tcp_template *tmpl = NULL;

    for (int i = 0; i < TCP_TX_SCAN; i++) {
        __u32 idx;
        __u32 cursor = *next;
        if (cursor >= count)
            cursor = 0;
        *next = cursor + 1;
        idx = first + cursor * cs->stride;
        if (idx >= MAX_TCP_FLOWS)
            continue;
        struct tcp_flow *f;
        if (global->slot_count)
            f = tcp_slot_flow(idx, global);
        else
            f = bpf_map_lookup_elem(&tcp_flow_map, &idx);
        if (!f)
            continue;
        __u32 group = f->template_id;
        tmpl = bpf_map_lookup_elem(&tcp_template_map, &group);
        if (!tmpl)
            return XDP_ABORTED;
        cfg = &tmpl->cfg;
        // Do not carry action state between scan attempts into the verifier.
        decision.act = (struct tcp_tx_action){0};
        decision.extra = (struct tcp_tx_extra){0};
        kind = tcp_tx_decide_mixed(f, tmpl, st, &decision, extended);
        if (kind != TXA_NONE && kind != TXA_CLOSED) {
            sel = f;
            break;
        }
        kind = TXA_NONE;
    }
    if (kind == TXA_NONE || !sel) {
        st->idle_iters++;
        return XDP_DROP;
    }

    int built;
    if (extended)
        built = tcp_template_build_ext(ctx, tmpl, cs, &decision.act, &decision.extra);
    else
        built = tcp_template_build(ctx, tmpl, cs, &decision.act);
    if (built >= 0 && extended)
        built = tcp_template_finish(ctx, tmpl, &decision.act, &decision.extra);
    if (built >= 0 && extended && mixed_has_payload && decision.act.len) {
        __u32 id = tmpl->payload_id;
        const struct tcp_payload *p = bpf_map_lookup_elem(&tcp_payload_map, &id);
        if (!p) {
            built = -1;
        } else if (p->period) {
            __u32 offset = tmpl->cfg.l4_off + 20 + tmpl->data_len;
            if (mixed_has_timestamps && decision.extra.timestamps)
                offset += 12;
            built = tcp_payload_write(ctx, offset, decision.act.len, decision.extra.stream_offset, p);
        }
    }
    if (built < 0) {
        st->build_errors++;
        return XDP_DROP;
    }

    kind = decision.act.kind;
    __sync_fetch_and_add(&sel->tx_pkts, 1);
    if (kind == TXA_DATA)
        __sync_fetch_and_add(&sel->tx_data, 1);
    else if (kind == TXA_RTX_TO || kind == TXA_RTX_DUPACK || kind == TXA_RTX_GBN)
        __sync_fetch_and_add(&sel->tx_rtx, 1);

    switch (kind) {
    case TXA_SYN:
        if (!sel->started) {
            sel->started = 1;
            st->started++;
        }
        st->syn_sent++;
        break;
    case TXA_DATA:
        st->data_segs++;
        st->data_bytes += decision.act.len;
        break;
    case TXA_FIN:
        st->fin_sent++;
        break;
    case TXA_RTX_TO:
        st->rtx_segs++;
        st->rtx_timeouts++;
        break;
    case TXA_RTX_DUPACK:
        st->rtx_segs++;
        st->rtx_dupack++;
        break;
    case TXA_RTX_GBN:
        st->rtx_segs++;
        break;
    case TXA_ACK:
        st->ack_probes++;
        break;
    case TXA_WND_PROBE:
        st->window_probes++;
        break;
    case TXA_RST:
        st->rst_sent++;
        break;
    default:
        break;
    }
    if (!global->drain && !global->abort) {
        struct pkt_state *ps = bpf_map_lookup_elem(&pkt_state_map, &zero);
        if (ps && ps->budget)
            ps->budget--;
    }
    return XDP_TX;
}

SEC("xdp")
int xdp_tx_tcp_mixed(struct xdp_md *ctx)
{
    return tcp_tx_run(ctx, 0);
}

SEC("xdp")
int xdp_tx_tcp_mixed_ext(struct xdp_md *ctx)
{
    return tcp_tx_run(ctx, 1);
}

// ---------------------------------------------------------------------------
// In-place reply: turn a received frame into a header-only TCP segment going
// back to its sender (shared by the client RX and the --tcp-server responder)
// ---------------------------------------------------------------------------

struct tcp_reply {
    __u32 seq;
    __u32 ack;
    __u16 mss; // MSS option value (opt_len != 0 only)
    __u8 flags;
    __u8 opt_len; // 0, or TCP_SYN_OPT_LEN for MSS + NOP + WS (SYN-ACK)
    __u8 wscale;  // window scale option; 0xFF = send NOPs instead of WS
};

// Rewrites the frame in place: MACs / IPs / ports swapped, TCP header (and
// optionally SYN options) from *r, payload removed, IP length / IPv4 header
// checksum / TCP checksum recomputed (pseudo header from the frame's own
// addresses). push_vlan re-inserts an 802.1Q tag that the receive path
// stripped (rx-vlan-offload / veth hwaccel). l3_off describes the received
// frame (14, or 18 when the tag is still in the frame). Returns 0 on success.
static __always_inline int tcp_reply_inplace(struct xdp_md *ctx, __u32 l3_off, __u8 ip_version, __u8 push_vlan, __u16 vlan_id,
                                             __u8 vlan_pcp, const struct tcp_reply *r)
{
    __u32 opt_len = r->opt_len ? TCP_SYN_OPT_LEN : 0;
    __u32 tcp_len = TCP_HDR_LEN + opt_len;
    __u32 l4_off = l3_off + (ip_version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
    __u32 hdr_len = l4_off + tcp_len;

    if (l3_off > 18)
        return -1;

    // Ports first: the frame is truncated below, but the TCP header survives.
    __u8 ports[4];
    if (bpf_xdp_load_bytes(ctx, l4_off, ports, sizeof(ports)) < 0)
        return -1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 cur_len = data_end - data;
    if (cur_len != hdr_len) {
        if (bpf_xdp_adjust_tail(ctx, (int)hdr_len - (int)cur_len) < 0)
            return -1;
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
    }
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    {
        __u8 tmp[ETH_ALEN];
        __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
    }

    __u64 tsum = IPPROTO_TCP + tcp_len;
    if (ip_version == 4) {
        struct iphdr *iph = data + l3_off;
        if ((void *)(iph + 1) > data_end)
            return -1;
        __be32 t = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = t;
        iph->tot_len = bpf_htons(sizeof(*iph) + tcp_len);
        iph->ttl = 64;
        iph->check = 0;
        __u64 isum = 0;
        __u16 *w = (__u16 *)iph;
#pragma unroll
        for (int i = 0; i < 10; i++)
            isum += bpf_ntohs(w[i]);
        iph->check = bpf_htons(tcp_csum_fold(isum));
#pragma unroll
        for (int i = 6; i < 10; i++) // saddr + daddr
            tsum += bpf_ntohs(w[i]);
    } else {
        struct ipv6hdr *ip6h = data + l3_off;
        if ((void *)(ip6h + 1) > data_end)
            return -1;
        struct in6_addr t = ip6h->saddr;
        ip6h->saddr = ip6h->daddr;
        ip6h->daddr = t;
        ip6h->payload_len = bpf_htons(tcp_len);
        ip6h->hop_limit = 64;
        __u16 *w = (__u16 *)ip6h;
#pragma unroll
        for (int i = 4; i < 20; i++) // saddr + daddr
            tsum += bpf_ntohs(w[i]);
    }

    __u8 th[TCP_HDR_LEN + TCP_SYN_OPT_LEN] = {0};
    th[0] = ports[2]; // source <- received destination
    th[1] = ports[3];
    th[2] = ports[0];
    th[3] = ports[1];
    put_be32(th + 4, r->seq);
    put_be32(th + 8, r->ack);
    th[12] = (__u8)((tcp_len / 4) << 4);
    th[13] = r->flags;
    put_be16(th + 14, 65535);
    if (opt_len) {
        th[20] = 2; // MSS
        th[21] = 4;
        put_be16(th + 22, r->mss);
        if (r->wscale != 0xFF) {
            th[24] = 1; // NOP
            th[25] = 3; // Window scale
            th[26] = 3;
            th[27] = r->wscale;
        } else {
            th[24] = 1;
            th[25] = 1;
            th[26] = 1;
            th[27] = 1;
        }
    }
    SUM16_BUF(tsum, th, TCP_HDR_LEN + TCP_SYN_OPT_LEN); // option area is zero when unused
    put_be16(th + 16, tcp_csum_fold(tsum));
    if (opt_len) {
        if (bpf_xdp_store_bytes(ctx, l4_off, th, TCP_HDR_LEN + TCP_SYN_OPT_LEN) < 0)
            return -1;
    } else {
        if (bpf_xdp_store_bytes(ctx, l4_off, th, TCP_HDR_LEN) < 0)
            return -1;
    }

    if (push_vlan) {
        // Re-insert the 802.1Q tag the receive path stripped.
        if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)) < 0)
            return -1;
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end)
            return -1;
        __u8 *p = data;
        __u8 macs[2 * ETH_ALEN];
        __builtin_memcpy(macs, p + sizeof(struct vlan_hdr), sizeof(macs));
        __builtin_memcpy(p, macs, sizeof(macs));
        struct vlan_hdr *vh = data + 2 * ETH_ALEN + 2;
        __u16 *tpid = data + 2 * ETH_ALEN;
        *tpid = bpf_htons(ETH_P_8021Q);
        // The original ethertype already sits at offset 16, which is exactly
        // h_vlan_encapsulated_proto of the new tag: only the TCI is written.
        vh->h_vlan_TCI = bpf_htons(((__u16)vlan_pcp << 13) | vlan_id);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// RX: consume packets of experiment flows, reply with ACKs in place
// ---------------------------------------------------------------------------

struct tcp_rx_info {
    __u32 seq;
    __u32 ack;
    __u32 payload_len;
    __u16 win;
    __u16 dport;
    __u16 mss; // MSS option of a SYN-ACK (0 = not present)
    __u8 flags;
    __u8 doff;
    __u8 wscale; // window-scale option of a SYN-ACK (0xFF = not present)
};

struct tcp_rx_timestamp {
    __u32 tsval;
    __u8 has_timestamp;
};

// Parse the MSS and window-scale options of a SYN / SYN-ACK. l4_off/doff are
// packet-derived; the loop is bounded (at most 10 options).
static __always_inline void tcp_parse_syn_opts(struct xdp_md *ctx, __u32 l4_off, __u32 doff, __u8 *ws_out, __u16 *mss_out)
{
    __u32 off = l4_off + TCP_HDR_LEN;
    __u32 end = l4_off + doff * 4;
    __u8 ws = 0xFF;
    __u16 mss = 0;

    for (int i = 0; i < 10; i++) {
        if (off + 1 > end)
            break;
        __u8 kind_len[2] = {0, 0};
        if (bpf_xdp_load_bytes(ctx, off, kind_len, 1) < 0)
            break;
        if (kind_len[0] == 0)
            break;
        if (kind_len[0] == 1) {
            off += 1;
            continue;
        }
        if (off + 2 > end)
            break;
        if (bpf_xdp_load_bytes(ctx, off + 1, kind_len + 1, 1) < 0)
            break;
        if (kind_len[1] < 2 || off + kind_len[1] > end)
            break;
        if (kind_len[0] == 2 && kind_len[1] == 4) {
            __u8 m[2];
            if (bpf_xdp_load_bytes(ctx, off + 2, m, 2) == 0)
                mss = ((__u16)m[0] << 8) | m[1];
        } else if (kind_len[0] == 3 && kind_len[1] == 3) {
            if (bpf_xdp_load_bytes(ctx, off + 2, &ws, 1) < 0)
                ws = 0xFF;
            else if (ws > 14)
                ws = 14;
        }
        off += kind_len[1];
    }
    *ws_out = ws;
    *mss_out = mss;
}

#include "xdp_tcp_timestamp.h"

// What TCP RX sends back (if anything) after updating the flow.
struct tcp_rx_resp {
    __u32 seq;
    __u32 ack;
    __u8 flags; // 0 = no reply
};

static __always_inline void tcp_rx_reply(struct tcp_rx_resp *r, __u32 seq, __u32 ack, __u8 flags)
{
    r->seq = seq;
    r->ack = ack;
    r->flags = flags;
}

// State machine under the flow lock; fills *r when a reply is needed.
// Replies (ACK / RST) use seq = snd_max: after a go-back-N rewind snd_nxt may
// lie below the peer's RCV.NXT, which would make the segment unacceptable.
static __always_inline void tcp_rx_update(struct tcp_flow *f, struct tcp_stats *st, const struct tcp_rx_info *in, __u16 cfg_mss,
                                          __u64 now, struct tcp_rx_resp *r, const struct tcp_rx_timestamp *ts,
                                          struct tcp_tx_extra *extra, const int timestamps, const int track_closed)
{
    __u8 flags = in->flags;
    __u8 need_ack = 0;

    bpf_spin_lock(&f->lock);
    __u8 state = f->state;
    if (timestamps && f->ts_enabled && !(flags & TCPF_RST)) {
        if (!ts->has_timestamp)
            goto out;
        if ((__s32)(ts->tsval - f->ts_recent) < 0 && (now <= f->ts_recent_ns || now - f->ts_recent_ns < 2073600000000000ULL)) {
            tcp_rx_reply(r, f->snd_max, f->rcv_nxt, TCPF_ACK);
            goto out;
        }
        if (seq_leq(in->seq, f->rcv_nxt) && (flags & TCPF_ACK) && seq_leq(f->snd_una, in->ack) && seq_leq(in->ack, f->snd_max)) {
            f->ts_recent = ts->tsval;
            f->ts_recent_ns = now;
        }
    }

    if (flags & TCPF_RST) {
        st->rst_rcvd++;
        if (state == TF_SYN_SENT) {
            // RFC 9293 3.10.7.3: in SYN-SENT a RST is acceptable only if it
            // acknowledges our SYN; leftovers of an earlier run are ignored.
            if ((flags & TCPF_ACK) && in->ack == f->iss + 1) {
                f->state = TF_FAILED;
                st->failed++;
            }
        } else if (tcp_flow_open(state)) {
            // RFC 5961 3.2: only an RST at exactly rcv_nxt resets the flow;
            // any other (a stale RST from an earlier connection on this
            // 4-tuple, a spoofed one) gets a challenge ACK, and a genuine
            // peer answers that with an RST at the right seq.
            if (in->seq == f->rcv_nxt) {
                f->state = TF_FAILED;
                st->failed++;
                st->failed_est++;
            } else {
                tcp_rx_reply(r, f->snd_max, f->rcv_nxt, TCPF_ACK);
                st->challenge_acks++;
            }
        }
        goto out;
    }

    if (state == TF_SYN_SENT) {
        if ((flags & (TCPF_SYN | TCPF_ACK)) == (TCPF_SYN | TCPF_ACK) && in->ack == f->iss + 1) {
            if (timestamps) {
                f->ts_enabled = ts->has_timestamp;
                if (ts->has_timestamp) {
                    f->ts_recent = ts->tsval;
                    f->ts_recent_ns = now;
                }
            }
            f->rcv_nxt = in->seq + 1;
            f->snd_una = f->iss + 1;
            f->wscale = (in->wscale == 0xFF) ? 0 : in->wscale;
            // RFC 7323 2.2: the window of a SYN / SYN-ACK is never scaled
            f->snd_wnd = (__u32)in->win;
            // Never send more than the peer can take (tunnel paths advertise
            // a smaller MSS). Without the option keep ours: every Linux peer
            // sends it.
            f->mss = (in->mss && in->mss < cfg_mss) ? in->mss : cfg_mss;
            f->state = TF_ESTABLISHED;
            f->last_ack_ns = now;
            f->dup_acks = 0;
            st->synack_rcvd++;
            st->established++;
            tcp_rx_reply(r, f->snd_max, f->rcv_nxt, TCPF_ACK);
        } else if (flags & TCPF_ACK) {
            // An ACK that does not ack our SYN: the peer still holds a
            // connection on this 4-tuple (an earlier, aborted run) and sends a
            // challenge ACK. RFC 9293: reply <SEQ=SEG.ACK><CTL=RST>, then let
            // TX resend the SYN once immediately.
            tcp_rx_reply(r, in->ack, 0, TCPF_RST);
            st->rst_sent++;
            if (!(f->syn_rst & 2))
                f->syn_rst = 1;
        } else {
            st->unexpected++;
        }
        goto out;
    }

    if (state == TF_DONE) {
        // The peer retransmits its FIN when our final ACK was lost (no
        // TIME_WAIT here): answer it again, otherwise it stays in LAST-ACK.
        if (flags & TCPF_FIN)
            tcp_rx_reply(r, f->snd_max, f->rcv_nxt, TCPF_ACK);
        goto out;
    }
    if (!tcp_flow_open(state)) {
        // CLOSED / FAILED / SKIPPED: the peer still talks to a flow we gave
        // up on. Reset it (exact seq from its ACK) so it does not linger into
        // the next run.
        if (flags & TCPF_ACK) {
            tcp_rx_reply(r, in->ack, 0, TCPF_RST);
            st->rst_sent++;
        }
        goto out;
    }
    if (!(flags & TCPF_ACK)) {
        st->unexpected++;
        goto out;
    }
    if (flags & TCPF_SYN) {
        // Retransmitted SYN-ACK: our handshake ACK was lost. Ack it again,
        // otherwise the peer keeps retransmitting and eventually resets.
        if (in->seq + 1 == f->rcv_nxt)
            tcp_rx_reply(r, f->snd_max, f->rcv_nxt, TCPF_ACK);
        else
            st->unexpected++;
        goto out;
    }

    st->acks_rcvd++;
    __u32 new_wnd = (__u32)in->win << f->wscale;
    // Only an ACK inside [snd_una, snd_max] may change the window: a
    // reordered older ACK (or one beyond what we sent) must not shrink it
    // (RFC 9293 3.10.7.4, SND.WL2 part; the peer sends no data, so WL1 is moot).
    __u8 ack_ok = seq_leq(f->snd_una, in->ack) && seq_leq(in->ack, f->snd_max);
    if (seq_after(in->ack, f->snd_una) && !seq_after(in->ack, f->snd_max)) {
        __u32 acked = in->ack - f->snd_una;
        // the FIN occupies one sequence number: do not count it as data
        if (state == TF_FIN_WAIT_1 && in->ack == f->snd_max)
            acked -= 1;
        f->bytes_acked += acked;
        st->bytes_acked += acked;
        f->snd_una = in->ack;
        if (seq_after(in->ack, f->snd_nxt)) // data the peer had buffered across a go-back-N rewind
            f->snd_nxt = in->ack;
        f->dup_acks = 0;
        f->rtx_pending = 0;
        f->rtx_retries = 0;
        f->last_ack_ns = now;
    } else if (in->ack == f->snd_una && in->payload_len == 0 && !(flags & (TCPF_SYN | TCPF_FIN)) && f->snd_max != f->snd_una &&
               new_wnd == f->snd_wnd) {
        // RFC 5681 duplicate ACK (a window update is not one)
        if (f->dup_acks < 255)
            f->dup_acks++;
        if (f->dup_acks == 3)
            f->rtx_pending = 1;
    }
    if (ack_ok)
        f->snd_wnd = new_wnd;

    if (in->payload_len > 0) {
        // the peer sent data: swallow it, acknowledge it
        __u32 end = in->seq + in->payload_len;
        if (!seq_after(in->seq, f->rcv_nxt) && seq_after(end, f->rcv_nxt))
            f->rcv_nxt = end; // only the part beyond rcv_nxt is new
        need_ack = 1;
    }
    if (flags & TCPF_FIN) {
        // accept the FIN only at its place in the sequence space
        if (!f->peer_fin && in->seq + in->payload_len == f->rcv_nxt) {
            f->peer_fin = 1;
            f->rcv_nxt += 1;
        }
        need_ack = 1;
    }

    if (state == TF_FIN_WAIT_1 && f->snd_una == f->snd_max) {
        if (f->peer_fin) {
            f->state = TF_DONE;
            st->done++;
        } else {
            f->state = TF_FIN_WAIT_2;
            f->fin_retries = 0;
            f->last_send_ns = now; // FIN_WAIT_2 probe timer
        }
    } else if (state == TF_FIN_WAIT_2 && f->peer_fin) {
        f->state = TF_DONE;
        st->done++;
    }
    if (need_ack)
        tcp_rx_reply(r, f->snd_max, f->rcv_nxt, TCPF_ACK);

out:
    if (timestamps && f->ts_enabled && r->flags) {
        extra->timestamps = 1;
        extra->tsval = tcp_timestamp_clock(f, now);
        extra->tsecr = f->ts_recent;
    }
    int closed = track_closed && !mixed_flow_closed(state) && mixed_flow_closed(f->state);
    bpf_spin_unlock(&f->lock);
    if (closed)
        mixed_count_closed(f);
}

#include "xdp_tcp_template_rx.h"

#endif // XDP_TCP_H
