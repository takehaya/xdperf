#include "xdp_prog.h"
#include "xdpcap.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <stdbool.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_tx(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    // Get per-CPU packet state
    struct pkt_state *state = bpf_map_lookup_elem(&pkt_state_map, &zero);
    if (!state) {
        DEBUG_PRINT("pkt_state_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 count = state->count;
    if (count == 0) {
        DEBUG_PRINT("count=0, skipping\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }
    if (count > MAX_PACKET_ENTRY)
        count = MAX_PACKET_ENTRY;

    __u32 local_idx = state->idx;
    if (local_idx >= count)
        local_idx = 0;

    // Use local_idx directly (each CPU has its own packets at indices 0..count-1)
    __u32 idx = local_idx;

    struct pkt_template *pt = bpf_map_lookup_elem(&tx_override_map, &idx);
    if (!pt) {
        DEBUG_PRINT("tx_override_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 tlen = pt->len;
    if (tlen > MAX_TEMPLATE_SIZE)
        tlen = MAX_TEMPLATE_SIZE;

    __u32 cur_len = data_end - data;
    if (cur_len != tlen) {
        int delta = (int)tlen - (int)cur_len;
        if (bpf_xdp_adjust_tail(ctx, delta) < 0) {
            DEBUG_PRINT("bpf_xdp_adjust_tail failed\n");
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
        }
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        if (data + tlen > data_end) {
            DEBUG_PRINT("data out of bounds\n");
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
        }

        // override payload
        if (data + tlen > data_end) {
            DEBUG_PRINT("data out of bounds\n");
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
        }
    }
    void *cursor = data;
    for (__u32 i = 0; i < MAX_TEMPLATE_SIZE; i++) {
        if (i >= tlen)
            break;

        if (cursor + 1 > data_end) {
            DEBUG_PRINT("cursor out of bounds\n");
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
        }

        *(__u8 *)cursor = pt->data[i];
        cursor++;
    }

    // next local index (within this CPU's range)
    __u32 next = local_idx + 1;
    if (next >= count)
        next = 0;
    state->idx = next;

    // sended packet stats
    struct datarec *rec = bpf_map_lookup_elem(&stats_map, &zero);
    if (!rec) {
        DEBUG_PRINT("stats_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }
    rec->rx_packets++;
    rec->rx_bytes += ctx->data_end - ctx->data;
    DEBUG_PRINT("tx: cnt=%u idx=%u len=%u\n", count, idx, ctx->data_end - ctx->data);
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_TX);
};

SEC("xdp")
int xdp_pass_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
};
