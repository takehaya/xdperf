#include "xdp_prog.h"
#include "xdpcap.h"
#include "xdp_utils.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
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

    __u32 idx = local_idx;

    struct pkt_template *pt = bpf_map_lookup_elem(&tx_override_map, &idx);
    if (!pt) {
        DEBUG_PRINT("tx_override_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 tlen = pt->len;
    if (tlen > MAX_TEMPLATE_SIZE)
        tlen = MAX_TEMPLATE_SIZE;
    // Minimum packet size check (Ethernet header = 14 bytes minimum)
    // This also ensures tlen > 0 for bpf_xdp_store_bytes
    if (tlen < sizeof(struct ethhdr)) {
        DEBUG_PRINT("packet too small: %u\n", tlen);
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 cur_len = data_end - data;
    if (cur_len != tlen) {
        int delta = (int)tlen - (int)cur_len;
        if (bpf_xdp_adjust_tail(ctx, delta) < 0) {
            DEBUG_PRINT("bpf_xdp_adjust_tail failed\n");
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
        }
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
    }

    // Bounds check for verifier
    if (data + tlen > data_end) {
        DEBUG_PRINT("data out of bounds\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    long ret = bpf_xdp_store_bytes(ctx, 0, pt->data, tlen);
    if (ret < 0) {
        DEBUG_PRINT("bpf_xdp_store_bytes failed: %ld\n", ret);
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // next local index
    __u32 next = local_idx + 1;
    if (next >= count)
        next = 0;
    state->idx = next;

    // stats
    struct datarec *rec = bpf_map_lookup_elem(&tx_stats_map, &zero);
    if (!rec) {
        DEBUG_PRINT("stats_map lookup failed\n");
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);
    }
    rec->packets++;
    rec->bytes += ctx->data_end - ctx->data;
    DEBUG_PRINT("tx: cnt=%u idx=%u len=%u\n", count, idx, ctx->data_end - ctx->data);
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_TX);
};

SEC("xdp")
int xdp_pass_dummy(struct xdp_md *ctx)
{
    return XDP_PASS;
};
SEC("xdp")
int xdp_rx(struct xdp_md *ctx)
{
    int key = 0;
    struct datarec *rec = bpf_map_lookup_elem(&rx_stats_map, &key);
    if (!rec)
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_ABORTED);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct vlan_hdr *vlan;
    __u16 eth_proto;
    void *l3_hdr;

    if (data + sizeof(*eth) > data_end)
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

    eth_proto = eth->h_proto;
    l3_hdr = data + sizeof(*eth);

    // Handle VLAN (single or double tagging)
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        vlan = l3_hdr;
        if ((void *)vlan + sizeof(*vlan) > data_end)
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

        eth_proto = vlan->h_vlan_encapsulated_proto;
        l3_hdr = (void *)vlan + sizeof(*vlan);

        // Check for double VLAN (QinQ)
        if (eth_proto == bpf_htons(ETH_P_8021Q)) {
            vlan = l3_hdr;
            if ((void *)vlan + sizeof(*vlan) > data_end)
                return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

            eth_proto = vlan->h_vlan_encapsulated_proto;
            l3_hdr = (void *)vlan + sizeof(*vlan);
        }
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        iph = l3_hdr;
        if ((void *)iph + sizeof(*iph) > data_end)
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

        // Swap MAC and IP addresses
        swap_mac(eth);
        swap_ipv4(iph);

        rec->packets++;
        rec->bytes += (__u64)(data_end - data);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = l3_hdr;
        if ((void *)ip6h + sizeof(*ip6h) > data_end)
            return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);

        // Swap MAC and IPv6 addresses
        swap_mac(eth);
        swap_ipv6(ip6h);

        rec->packets++;
        rec->bytes += (__u64)(data_end - data);
    } else {
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
    }
    if (swap_resp == 0) {
        return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);
    }
    return xdpcap_exit(ctx, &xdpcap_hook, XDP_TX);
}
