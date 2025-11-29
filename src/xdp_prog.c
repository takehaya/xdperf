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

    // Get template count from map
    __u32 *pcount = bpf_map_lookup_elem(&template_count_map, &zero);
    __u32 template_count = pcount ? *pcount : 1;
    if (template_count == 0)
        template_count = 1;

    // Get current index from per-CPU state
    __u32 *pidx = bpf_map_lookup_elem(&seq_state_map, &zero);
    __u32 idx = pidx ? (*pidx % template_count) : 0;

    struct pkt_template *pt = bpf_map_lookup_elem(&tx_override_map, &idx);
    if (!pt) {
        DEBUG_PRINT("tx_override_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 tlen = pt->len;
    if (tlen > MAX_TEMPLATE_SIZE)
        tlen = MAX_TEMPLATE_SIZE;
    if (tlen == 0) {
        DEBUG_PRINT("template length is 0\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 cur_len = data_end - data;
    DEBUG_PRINT("cur_len=%u, tlen=%u\n", cur_len, tlen);
    if (cur_len != tlen) {
        int delta = (int)tlen - (int)cur_len;
        if (bpf_xdp_adjust_tail(ctx, delta) < 0) {
            DEBUG_PRINT("bpf_xdp_adjust_tail failed: delta=%d\n", delta);
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
        }
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
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

    // sended packet stats
    struct datarec *rec = bpf_map_lookup_elem(&stats_map, &zero);
    if (!rec) {
        DEBUG_PRINT("stats_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }
    rec->rx_packets++;
    rec->rx_bytes += ctx->data_end - ctx->data;

    // Update index for next packet (round-robin through templates)
    if (pidx) {
        *pidx = (idx + 1) % template_count;
    }

    DEBUG_PRINT("tx packet len=%u, iface=%d, idx=%u\n", ctx->data_end - ctx->data, ctx->ingress_ifindex, idx);
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_TX);
};

SEC("xdp")
int xdp_pass_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
};
