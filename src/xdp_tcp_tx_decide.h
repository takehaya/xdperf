// TCP TX decision, compiled twice from xdp_tcp.h: tcp_tx_decide (one-way,
// TCP_DECIDE_XCHG 0) and tcp_tx_decide_xchg (request/response rounds,
// TCP_DECIDE_XCHG 1). The preprocessor, not a constant argument, removes the
// round logic: the one-way function must stay the same code as before rounds
// existed, or 6.1's verifier spends more on every one-way TX program.
// No include guard on purpose.
#if !defined(TCP_DECIDE_NAME) || !defined(TCP_DECIDE_XCHG)
#error "define TCP_DECIDE_NAME and TCP_DECIDE_XCHG before including xdp_tcp_tx_decide.h"
#endif

// Returns the action kind; fills *a. No helper calls inside the lock region.
static __always_inline int TCP_DECIDE_NAME(struct tcp_flow *f, const struct tcp_cfg *cfg, struct tcp_stats *st, __u64 now,
                                           struct tcp_tx_action *a, struct tcp_tx_extra *extra, const int mixed_mode,
                                           const int timestamps, const int track_closed, int allow_start)
{
    int kind = TXA_NONE;
    __u64 rto = cfg->rto_ns;
    // Scheduling and TCP decisions share one stop flag, even during template updates.
    __u32 zero = 0;
    struct tcp_cfg *global = bpf_map_lookup_elem(&tcp_cfg_map, &zero);
    if (!global)
        return TXA_NONE;
    struct tcp_load *load = bpf_map_lookup_elem(&tcp_load_map, &zero);
    if (!load)
        return TXA_NONE;
    __u32 opened = 0;
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
        } else if ((!global->start_ns || now >= global->start_ns) && (!global->end_ns || now < global->end_ns) &&
                   (!global->target_cps || allow_start)) {
            f->state = TF_SYN_SENT;
#if TCP_DECIDE_XCHG
            // A reused slot (connections mode) starts its rounds again.
            f->rx_bytes = f->last_rx_ns = f->round_start_ns = 0;
            f->rtt_sum_ns = f->rtt_max_ns = f->rtt_samples = 0;
            f->rounds_done = 0;
#endif
            opened = __sync_fetch_and_add(&load->in_use, 1) + 1;
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
#if TCP_DECIDE_XCHG
        int xchg = tcp_flow_exchange(1, f, cfg->until_fin);
        __u8 stop = drain;
        if (xchg) {
            // One request (Q = bytes_target, 0 = none) per received response.
            __u64 target = f->bytes_target * tcp_xchg_rounds_allowed(f, cfg->until_fin);
            remaining = target > f->bytes_acked ? target - f->bytes_acked : 0;
            // The peer closed: no new request, only what is in flight.
            if (f->peer_fin)
                stop = 1;
        } else // ... if (f->bytes_target): one statement either way
#endif
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
#if TCP_DECIDE_XCHG
        } else if (!stop && remaining > (__u64)in_flight) {
            avail = remaining - in_flight;
            // A segment never spans two requests: the payload pattern and the
            // round timer restart at each request.
            if (xchg && f->bytes_target) {
                __u64 left = f->bytes_target - (f->bytes_acked + in_flight) % f->bytes_target;
                if (avail > left)
                    avail = left;
            }
        }
#else
        } else if (!drain && remaining > (__u64)in_flight) {
            avail = remaining - in_flight;
        }
#endif
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
#if TCP_DECIDE_XCHG
                // First byte of a request: RX clears the timer when the response is in.
                if (xchg && !rexmit && !f->round_start_ns && (f->bytes_acked + in_flight) % f->bytes_target == 0)
                    f->round_start_ns = now;
#endif
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
#if TCP_DECIDE_XCHG
            if (xchg && !stop && (cfg->close_by_server || cfg->until_fin || !tcp_xchg_all_rounds(f))) {
                // Waiting for a response (or the peer FIN): no RTO or persist
                // timer runs with nothing outstanding, so time the silence.
                __u64 since = f->last_send_ns > f->last_rx_ns ? f->last_send_ns : f->last_rx_ns;
                if (cfg->resp_timeout_ms && now > since && now - since > (__u64)cfg->resp_timeout_ms * 1000000) {
                    kind = tcp_tx_fail(f, st, a);
                    st->resp_timeouts++;
                }
                break;
            }
#endif
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
#if TCP_DECIDE_XCHG
        // A response still arriving after our FIN (drain) restarts the probe
        // timer. last_rx_ns comes from the RX CPU's clock: never go backwards.
        if (tcp_flow_exchange(1, f, cfg->until_fin) && f->last_rx_ns > f->last_send_ns &&
            (now < f->last_rx_ns || now - f->last_rx_ns <= (rto << f->fin_retries)))
            break;
#endif
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
#if TCP_DECIDE_XCHG
    // Every request starts at the beginning of the pattern.
    if (mixed_mode && mixed_has_payload && a->len && tcp_flow_exchange(1, f, cfg->until_fin) && f->bytes_target)
        extra->stream_offset %= f->bytes_target;
#endif
    if (mixed_mode && mixed_has_timestamps && timestamps) {
        __u32 clock = now / 1000000;
        if ((state != TF_CLOSED || f->connection_id >= global->flow_count) && (__s32)(clock - f->ts_clock) < 0)
            clock = f->ts_clock;
        f->ts_clock = clock;
        extra->timestamps = (a->flags & TCPF_SYN) || f->ts_enabled;
        extra->tsval = clock;
        extra->tsecr = (a->flags & TCPF_ACK) ? f->ts_recent : 0;
    }
    if (!mixed_flow_closed(state) && mixed_flow_closed(f->state)) {
        f->closed_ns = now;
        if (state != TF_CLOSED && load && load->in_use)
            __sync_fetch_and_sub(&load->in_use, 1);
    }
    int closed = track_closed && !mixed_flow_closed(state) && mixed_flow_closed(f->state);
    bpf_spin_unlock(&f->lock);
    if (closed)
        mixed_count_closed(f);
    if (opened)
        tcp_count_peak(opened);
    a->kind = kind;
    return kind;
}
