#include "xdp_prog.h"
#include "xdp_differential.h"
#include "xdp_checksum.h"
#include "xdpcap.h"
#include "xdp_utils.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
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
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 count = state->count;
    if (count == 0) {
        DEBUG_PRINT("count=0, skipping\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
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
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 tlen = pt->len;
    if (tlen > MAX_TEMPLATE_SIZE)
        tlen = MAX_TEMPLATE_SIZE;
    // Minimum packet size check (Ethernet header = 14 bytes minimum)
    // This also ensures tlen > 0 for bpf_xdp_store_bytes
    if (tlen < sizeof(struct ethhdr)) {
        DEBUG_PRINT("packet too small: %u\n", tlen);
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 cur_len = data_end - data;
    if (cur_len != tlen) {
        int delta = (int)tlen - (int)cur_len;
        if (bpf_xdp_adjust_tail(ctx, delta) < 0) {
            DEBUG_PRINT("bpf_xdp_adjust_tail failed\n");
            RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
        }
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
    }

    // Bounds check for verifier
    if (data + tlen > data_end) {
        DEBUG_PRINT("data out of bounds\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    long ret = bpf_xdp_store_bytes(ctx, 0, pt->data, tlen);
    if (ret < 0) {
        DEBUG_PRINT("bpf_xdp_store_bytes failed: %ld\n", ret);
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
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
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }
    rec->packets++;
    rec->bytes += ctx->data_end - ctx->data;
    DEBUG_PRINT("tx: cnt=%u idx=%u len=%u\n", count, idx, ctx->data_end - ctx->data);
    RETURN_ACTION(ctx, &xdpcap_hook, XDP_TX);
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
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct vlan_hdr *vlan;
    __u16 eth_proto;
    void *l3_hdr;

    if (data + sizeof(*eth) > data_end)
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_PASS);

    eth_proto = eth->h_proto;
    l3_hdr = data + sizeof(*eth);

    // Handle VLAN (single or double tagging)
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        vlan = l3_hdr;
        if ((void *)vlan + sizeof(*vlan) > data_end)
            RETURN_ACTION(ctx, &xdpcap_hook, XDP_PASS);

        eth_proto = vlan->h_vlan_encapsulated_proto;
        l3_hdr = (void *)vlan + sizeof(*vlan);

        // Check for double VLAN (QinQ)
        if (eth_proto == bpf_htons(ETH_P_8021Q)) {
            vlan = l3_hdr;
            if ((void *)vlan + sizeof(*vlan) > data_end)
                RETURN_ACTION(ctx, &xdpcap_hook, XDP_PASS);

            eth_proto = vlan->h_vlan_encapsulated_proto;
            l3_hdr = (void *)vlan + sizeof(*vlan);
        }
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        iph = l3_hdr;
        if ((void *)iph + sizeof(*iph) > data_end)
            RETURN_ACTION(ctx, &xdpcap_hook, XDP_PASS);

        // Swap MAC and IP addresses
        swap_mac(eth);
        swap_ipv4(iph);

        rec->packets++;
        rec->bytes += (__u64)(data_end - data);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = l3_hdr;
        if ((void *)ip6h + sizeof(*ip6h) > data_end)
            RETURN_ACTION(ctx, &xdpcap_hook, XDP_PASS);

        // Swap MAC and IPv6 addresses
        swap_mac(eth);
        swap_ipv6(ip6h);

        rec->packets++;
        rec->bytes += (__u64)(data_end - data);
    } else {
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_PASS);
    }
    if (swap_resp == 0) {
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_DROP);
    }
    RETURN_ACTION(ctx, &xdpcap_hook, XDP_TX);
}

// Apply a single diff value to the packet
// Uses bpf_xdp_store_bytes() to avoid verifier issues with variable-offset writes
static __always_inline int apply_diff(struct xdp_md *ctx, struct diff_value *dv)
{
    __u16 offset = dv->offset;
    __u8 size = dv->size;
    __u32 value = dv->value;

    if (size == 0 || offset == 0xFFFF)
        return 0; // Skip empty diff

    // Use bpf_xdp_store_bytes which handles bounds checking internally
    // This avoids verifier issues with variable-offset packet writes
    switch (size) {
    case 1: {
        __u8 v = (__u8)value;
        if (bpf_xdp_store_bytes(ctx, offset, &v, 1) < 0)
            return -1;
        break;
    }
    case 2: {
        __be16 v = bpf_htons((__u16)value);
        if (bpf_xdp_store_bytes(ctx, offset, &v, 2) < 0)
            return -1;
        break;
    }
    case 4: {
        __be32 v = bpf_htonl(value);
        if (bpf_xdp_store_bytes(ctx, offset, &v, 4) < 0)
            return -1;
        break;
    }
    default:
        return -1;
    }

    return 0;
}

// Recalculate checksum using bpf_xdp_load_bytes/bpf_xdp_store_bytes
// to avoid verifier issues with variable-offset packet access
static __always_inline int recalc_checksum(struct xdp_md *ctx, struct checksum_meta *meta, __u16 pkt_len)
{
    __u16 csum;
    __u16 transport_len;

    switch (meta->csum_type) {
    case CSUM_TYPE_IPV4_HEADER:
        csum = calc_ipv4_header_csum(ctx, meta->ip_header_offset);
        if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
            return -1;
        break;

    case CSUM_TYPE_UDP_IPV4:
    case CSUM_TYPE_TCP_IPV4: {
        // Load IP header to get transport length
        struct iphdr iph;
        if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset, &iph, sizeof(iph)) < 0)
            return -1;
        transport_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4);
    }
        csum = calc_transport_csum_ipv4(ctx, meta->ip_header_offset, meta->header_start, transport_len,
                                        meta->csum_type == CSUM_TYPE_UDP_IPV4 ? IPPROTO_UDP : IPPROTO_TCP);
        if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
            return -1;
        break;

    case CSUM_TYPE_UDP_IPV6:
    case CSUM_TYPE_TCP_IPV6:
    case CSUM_TYPE_ICMPV6: {
        // Load IPv6 header to get payload length
        struct ipv6hdr ip6h;
        if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset, &ip6h, sizeof(ip6h)) < 0)
            return -1;
        transport_len = bpf_ntohs(ip6h.payload_len);
        __u8 proto;
        switch (meta->csum_type) {
        case CSUM_TYPE_UDP_IPV6:
            proto = IPPROTO_UDP;
            break;
        case CSUM_TYPE_TCP_IPV6:
            proto = IPPROTO_TCP;
            break;
        default:
            proto = IPPROTO_ICMPV6;
            break;
        }
        csum = calc_transport_csum_ipv6(ctx, meta->ip_header_offset, meta->header_start, transport_len, proto);
        if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
            return -1;
        break;
    }

    default:
        return -1;
    }

    return 0;
}

SEC("xdp")
int xdp_tx_differential(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    // 1. Get per-CPU packet state
    struct diff_pkt_state *state = bpf_map_lookup_elem(&diff_pkt_state_map, &zero);
    if (!state) {
        DEBUG_PRINT("diff_pkt_state_map lookup failed\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 count = state->count;
    if (count == 0) {
        DEBUG_PRINT("diff count=0, skipping\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }
    if (count > MAX_DIFF_ENTRIES)
        count = MAX_DIFF_ENTRIES;

    __u32 local_idx = state->idx;
    if (local_idx >= count)
        local_idx = 0;

    // 2. Get base packet
    struct base_packet *base = bpf_map_lookup_elem(&base_packet_map, &zero);
    if (!base) {
        DEBUG_PRINT("base_packet_map lookup failed\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 3. Get diff entry for current index
    struct diff_entry *diff = bpf_map_lookup_elem(&diff_map, &local_idx);
    if (!diff) {
        DEBUG_PRINT("diff_map lookup failed\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 4. Determine target packet length
    __u16 target_len = diff->pkt_len;
    if (target_len == 0)
        target_len = base->len;
    if (target_len > MAX_TEMPLATE_SIZE)
        target_len = MAX_TEMPLATE_SIZE;
    if (target_len < sizeof(struct ethhdr)) {
        DEBUG_PRINT("packet too small: %u\n", target_len);
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 5. Adjust packet size
    __u32 cur_len = data_end - data;
    if (cur_len != target_len) {
        int delta = (int)target_len - (int)cur_len;
        if (bpf_xdp_adjust_tail(ctx, delta) < 0) {
            DEBUG_PRINT("bpf_xdp_adjust_tail failed\n");
            RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
        }
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
    }

    // Bounds check for verifier
    if (data + target_len > data_end) {
        DEBUG_PRINT("data out of bounds\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

// 6. Copy base packet
// The verifier loses scalar bounds after helper calls.
// Solution: Copy in fixed-size chunks with compile-time constants.
// Require minimum 64 byte packets for differential mode.
#define COPY_CHUNK_SIZE 64

    // Require minimum packet size of 64 bytes
    if (target_len < COPY_CHUNK_SIZE) {
        DEBUG_PRINT("packet too small for differential mode: %u\n", target_len);
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // First chunk: always copy 64 bytes
    long ret1 = bpf_xdp_store_bytes(ctx, 0, base->data, COPY_CHUNK_SIZE);
    if (ret1 < 0) {
        DEBUG_PRINT("bpf_xdp_store_bytes chunk1 failed: %ld\n", ret1);
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

// Second chunk: copy remaining bytes if packet > 64 bytes
// Use fixed-size chunks with compile-time constant for verifier
// Support up to 1600 bytes (25 chunks of 64 bytes)
#define MAX_COPY_CHUNKS 25

#pragma unroll
    for (int chunk = 1; chunk <= MAX_COPY_CHUNKS; chunk++) {
        __u32 offset = chunk * COPY_CHUNK_SIZE;

        // Check if we need this chunk
        if (target_len <= offset)
            break;

        // Check if this is a full chunk or partial chunk
        if (target_len >= offset + COPY_CHUNK_SIZE) {
            // Full chunk - use constant size
            long ret = bpf_xdp_store_bytes(ctx, offset, base->data + offset, COPY_CHUNK_SIZE);
            if (ret < 0) {
                DEBUG_PRINT("bpf_xdp_store_bytes chunk %d failed\n", chunk);
                break;
            }
        } else {
            // Last partial chunk - compute remaining bytes
            // Use signed arithmetic so compiler doesn't optimize away the < 1 check
            __s32 remaining_signed = (__s32)target_len - (__s32)offset;

            // Bounds check with signed comparison - compiler can't optimize this away
            if (remaining_signed < 1 || remaining_signed >= COPY_CHUNK_SIZE)
                break;

            // Convert to unsigned after bounds are established
            __u32 remaining = (__u32)remaining_signed;

            // Barrier to ensure verifier sees the bounded value
            asm volatile("" : "+r"(remaining));

            long ret = bpf_xdp_store_bytes(ctx, offset, base->data + offset, remaining);
            if (ret < 0) {
                DEBUG_PRINT("bpf_xdp_store_bytes last chunk failed\n");
            }
            break; // This was the last chunk
        }
    }

    // Refresh pointers after store
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // Re-validate packet bounds for verifier after bpf_xdp_store_bytes
    // The verifier loses bounds tracking after helper calls
    if (data + target_len > data_end) {
        DEBUG_PRINT("packet size mismatch after store\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 7. Apply diffs (unrolled loop for max 8 diffs)
    __u8 diff_count = diff->diff_count;
    if (diff_count > MAX_DIFFS_PER_PACKET)
        diff_count = MAX_DIFFS_PER_PACKET;

#pragma unroll
    for (int i = 0; i < MAX_DIFFS_PER_PACKET; i++) {
        if (i >= diff_count)
            break;
        if (apply_diff(ctx, &diff->diffs[i]) < 0) {
            DEBUG_PRINT("apply_diff failed at %d\n", i);
        }
    }

    // Refresh pointers after apply_diff calls (bpf_xdp_store_bytes may invalidate them)
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // Re-establish packet bounds for verifier after pointer refresh
    if (data + target_len > data_end) {
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 8. Recalculate checksums
    __u8 checksum_count = base->checksum_count;
    if (checksum_count > MAX_CHECKSUM_ENTRIES)
        checksum_count = MAX_CHECKSUM_ENTRIES;

#pragma unroll
    for (int i = 0; i < MAX_CHECKSUM_ENTRIES; i++) {
        if (i >= checksum_count)
            break;
        __u32 csum_idx = i;
        struct checksum_meta *meta = bpf_map_lookup_elem(&checksum_meta_map, &csum_idx);
        if (!meta)
            break;
        if (recalc_checksum(ctx, meta, target_len) < 0) {
            DEBUG_PRINT("recalc_checksum failed at %d\n", i);
        }
    }

    // 9. Update index (round-robin)
    __u32 next = local_idx + 1;
    if (next >= count)
        next = 0;
    state->idx = next;

    // 10. Update stats
    struct diff_datarec *rec = bpf_map_lookup_elem(&diff_tx_stats_map, &zero);
    if (rec) {
        rec->packets++;
        rec->bytes += target_len;
    }

    DEBUG_PRINT("diff_tx: cnt=%u idx=%u len=%u\n", count, local_idx, target_len);
    RETURN_ACTION(ctx, &xdpcap_hook, XDP_TX);
}
