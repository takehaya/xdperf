#include "xdp_prog.h"
#include "xdp_packet.h"
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

// Incremental checksum calculation assumes little-endian architecture.
// Big-endian systems (e.g., s390x) are not supported and will produce
// incorrect checksums. The bpf_bpfeb.o is generated but should not be used.

char _license[] SEC("license") = "GPL";

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

    // Handle VLAN (single or double tagging).
    // Note: Triple-tagged packets (e.g., 802.1ad + 802.1Q + 802.1Q) are not supported.
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
// new_value is stored in big-endian (network byte order)
// Note: __noinline prevents verifier state explosion when called from unrolled loop
static __noinline int apply_diff(struct xdp_md *ctx, struct diff_value *dv)
{
    __u16 offset = dv->offset;
    __u8 size = dv->size;

    if (size == 0 || offset == 0xFFFF)
        return 0; // Skip empty diff

    // Use bpf_xdp_store_bytes which handles bounds checking internally
    // This avoids verifier issues with variable-offset packet writes
    // new_value is already in network byte order, so write directly
    // Reduce switch cases to minimize verifier state explosion
    // Common cases (1, 2, 4) are explicit, others use variable size
    switch (size) {
    case 1:
        if (bpf_xdp_store_bytes(ctx, offset, dv->new_value, 1) < 0)
            return -1;
        break;
    case 2:
        if (bpf_xdp_store_bytes(ctx, offset, dv->new_value, 2) < 0)
            return -1;
        break;
    case 4:
        if (bpf_xdp_store_bytes(ctx, offset, dv->new_value, 4) < 0)
            return -1;
        break;
    default:
        // For sizes 6, 8, 16: use size directly (verifier tracks size is bounded)
        if (size > 16)
            return -1;
        if (bpf_xdp_store_bytes(ctx, offset, dv->new_value, size) < 0)
            return -1;
        break;
    }

    return 0;
}

// Recalculate checksum from scratch using bpf_xdp_load_bytes/bpf_xdp_store_bytes
// Used when packet length changes (incremental update not possible)
// This is O(packet_length) - only use when necessary
// Note: __noinline prevents verifier state explosion when called from loops
static __noinline int recalc_checksum(struct xdp_md *ctx, struct checksum_meta *meta, __u16 pkt_len)
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
        csum = calc_transport_csum_ipv4(ctx, meta->ip_header_offset, meta->header_start, transport_len,
                                        meta->csum_type == CSUM_TYPE_UDP_IPV4 ? IPPROTO_UDP : IPPROTO_TCP);
        if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
            return -1;
        break;
    }

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

// Update IP and transport layer length fields when packet length changed
// Must be called after base packet copy, before checksum recalculation
// Note: __noinline prevents verifier state explosion
static __noinline int update_packet_lengths(struct xdp_md *ctx, __u16 target_len)
{
    // Load Ethernet header to check protocol
    struct ethhdr eth;
    if (bpf_xdp_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
        return -1;

    __u16 eth_proto = eth.h_proto;
    __u16 l3_offset = sizeof(struct ethhdr);

    // Handle VLAN (single or double).
    // Note: Triple-tagged packets are not supported.
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        __be16 vlan_proto;
        if (bpf_xdp_load_bytes(ctx, l3_offset + 2, &vlan_proto, 2) < 0)
            return -1;
        eth_proto = vlan_proto;
        l3_offset += 4;

        // Double VLAN (QinQ)
        if (eth_proto == bpf_htons(ETH_P_8021Q)) {
            if (bpf_xdp_load_bytes(ctx, l3_offset + 2, &vlan_proto, 2) < 0)
                return -1;
            eth_proto = vlan_proto;
            l3_offset += 4;
        }
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        // IPv4: update tot_len (offset 2 from IP header)
        __u16 ip_len = target_len - l3_offset;
        __be16 ip_len_be = bpf_htons(ip_len);
        if (bpf_xdp_store_bytes(ctx, l3_offset + 2, &ip_len_be, 2) < 0)
            return -1;

        // Get protocol from IP header (offset 9)
        __u8 proto;
        if (bpf_xdp_load_bytes(ctx, l3_offset + 9, &proto, 1) < 0)
            return -1;

        // Get IHL (IP Header Length) from first byte
        __u8 version_ihl;
        if (bpf_xdp_load_bytes(ctx, l3_offset, &version_ihl, 1) < 0)
            return -1;
        __u16 ihl = (version_ihl & 0x0F) * 4;
        __u16 l4_offset = l3_offset + ihl;

        if (proto == IPPROTO_UDP) {
            // UDP: update len field (offset 4 from UDP header)
            __u16 udp_len = target_len - l4_offset;
            __be16 udp_len_be = bpf_htons(udp_len);
            if (bpf_xdp_store_bytes(ctx, l4_offset + 4, &udp_len_be, 2) < 0)
                return -1;
        }
        // TCP doesn't have a length field in header
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6: update payload_len (offset 4 from IPv6 header)
        __u16 payload_len = target_len - l3_offset - 40; // 40 = IPv6 header size
        __be16 payload_len_be = bpf_htons(payload_len);
        if (bpf_xdp_store_bytes(ctx, l3_offset + 4, &payload_len_be, 2) < 0)
            return -1;

        // Get next header (protocol) from IPv6 header (offset 6)
        __u8 proto;
        if (bpf_xdp_load_bytes(ctx, l3_offset + 6, &proto, 1) < 0)
            return -1;

        __u16 l4_offset = l3_offset + 40;

        if (proto == IPPROTO_UDP) {
            // UDP: update len field
            __u16 udp_len = target_len - l4_offset;
            __be16 udp_len_be = bpf_htons(udp_len);
            if (bpf_xdp_store_bytes(ctx, l4_offset + 4, &udp_len_be, 2) < 0)
                return -1;
        }
    }

    return 0;
}

// Fold bpf_csum_diff result to 16-bit checksum
static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    __u32 sum = (__u32)csum;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

// Check if a diff affects a particular checksum.
// Assumption: dv->offset + dv->size does not overflow __u16.
// This is guaranteed because valid packet offsets are < 2048 (MAX_TEMPLATE_SIZE)
// and size is at most 16 bytes (see diff_value struct).
// Note: __noinline prevents verifier state explosion when called from loops
static __noinline bool diff_affects_checksum(struct diff_value *dv, struct checksum_meta *meta, __u16 pkt_len)
{
    __u16 diff_start = dv->offset;
    __u16 diff_end = dv->offset + dv->size; // Safe: offset < 2048, size <= 16

    switch (meta->csum_type) {
    case CSUM_TYPE_IPV4_HEADER: {
        // IPv4 header checksum covers [ip_offset, ip_offset + 20)
        __u16 ip_start = meta->ip_header_offset;
        __u16 ip_end = ip_start + 20;
        return diff_start < ip_end && diff_end > ip_start;
    }
    case CSUM_TYPE_UDP_IPV4:
    case CSUM_TYPE_TCP_IPV4: {
        // Pseudo-header: src IP at ip_offset+12, dst IP at ip_offset+16
        __u16 src_ip = meta->ip_header_offset + 12;
        __u16 dst_ip_end = meta->ip_header_offset + 20;
        if (diff_start < dst_ip_end && diff_end > src_ip)
            return true;
        // Transport layer
        return diff_start < pkt_len && diff_end > meta->header_start;
    }
    case CSUM_TYPE_UDP_IPV6:
    case CSUM_TYPE_TCP_IPV6:
    case CSUM_TYPE_ICMPV6: {
        // IPv6 pseudo-header: src/dst addresses at ip_offset+8 to ip_offset+40
        __u16 src_ip = meta->ip_header_offset + 8;
        __u16 dst_ip_end = meta->ip_header_offset + 40;
        if (diff_start < dst_ip_end && diff_end > src_ip)
            return true;
        // Transport layer
        return diff_start < pkt_len && diff_end > meta->header_start;
    }
    default:
        return false;
    }
}

// Process a single diff for checksum update
// Note: __noinline prevents verifier state explosion from size-based branching
static __noinline __wsum apply_single_csum_diff(struct diff_value *dv, struct checksum_meta *meta, __u16 pkt_len, __wsum csum)
{
    // Skip if this diff doesn't affect the checksum
    if (!diff_affects_checksum(dv, meta, pkt_len))
        return csum;

    // Get byte position within 16-bit word (0=high byte, 1=low byte)
    __u8 word_pos = dv->offset & 1;

    // Construct old and new 4-byte values with the diff at the correct position
    // Padding bytes are identical in old and new, so they cancel out in bpf_csum_diff
    union {
        __be32 val;
        __u8 bytes[4];
    } old_u, new_u;

    // Initialize with zeros (padding)
    old_u.val = 0;
    new_u.val = 0;

    // old_value/new_value are stored in network byte order (big-endian)
    // Little-endian checksum calculation (see compile-time check above).
    // csum_partial loads 32-bit values as LE and folds: fold(0xAABBCCDD) = 0xCCDD + 0xAABB
    // Use __builtin_memcpy + bpf_ntoh* to minimize verifier state explosion
    // (individual byte accesses in unrolled loops cause state explosion)
    if (dv->size == 1) {
        if (word_pos == 0) {
            // Even offset = high byte of 16-bit word
            // On LE: bytes[3] maps to high16 bits, folds to 0xVV00
            old_u.bytes[3] = dv->old_value[0];
            new_u.bytes[3] = dv->new_value[0];
        } else {
            // Odd offset = low byte of 16-bit word
            // On LE: bytes[0] maps to low16 bits, folds to 0x00VV
            old_u.bytes[0] = dv->old_value[0];
            new_u.bytes[0] = dv->new_value[0];
        }
    } else if (dv->size == 2) {
        // 2-byte value: stored as BE, convert to LE using bpf_ntohs
        // BE [0x04, 0xD2] → bpf_ntohs → LE 0x04D2 → stored at bytes[0:1]
        // Note: 2-byte values at odd offsets would require special handling,
        // but in practice protocol fields are always word-aligned.
        if (word_pos != 0) {
            DEBUG_PRINT("Warning: 2-byte diff at odd offset %u may cause incorrect checksum\n", dv->offset);
        }
        __be16 old_be16, new_be16;
        __builtin_memcpy(&old_be16, dv->old_value, 2);
        __builtin_memcpy(&new_be16, dv->new_value, 2);
        *(__u16 *)&old_u.bytes[0] = bpf_ntohs(old_be16);
        *(__u16 *)&new_u.bytes[0] = bpf_ntohs(new_be16);
    } else if (dv->size == 4) {
        // 4-byte value: stored as BE, convert to LE using bpf_ntohl
        __be32 old_be32, new_be32;
        __builtin_memcpy(&old_be32, dv->old_value, 4);
        __builtin_memcpy(&new_be32, dv->new_value, 4);
        old_u.val = bpf_ntohl(old_be32);
        new_u.val = bpf_ntohl(new_be32);
    } else if (dv->size == 6) {
        // 6-byte value (MAC address): process as 4 bytes + 2 bytes
        // First 4 bytes
        __be32 old_be32, new_be32;
        __builtin_memcpy(&old_be32, &dv->old_value[0], 4);
        __builtin_memcpy(&new_be32, &dv->new_value[0], 4);
        __u32 old_le = bpf_ntohl(old_be32);
        __u32 new_le = bpf_ntohl(new_be32);
        csum = bpf_csum_diff(&old_le, 4, &new_le, 4, csum);

        // Remaining 2 bytes (with zero padding)
        __be16 old_be16, new_be16;
        __builtin_memcpy(&old_be16, &dv->old_value[4], 2);
        __builtin_memcpy(&new_be16, &dv->new_value[4], 2);
        old_u.val = 0;
        new_u.val = 0;
        *(__u16 *)&old_u.bytes[0] = bpf_ntohs(old_be16);
        *(__u16 *)&new_u.bytes[0] = bpf_ntohs(new_be16);
        DEBUG_PRINT("  csum_diff: size 6, processed 4+2 bytes\n");
    } else if (dv->size == 8) {
        // 8-byte value: process as two 4-byte chunks
        __be32 old_be32_0, new_be32_0, old_be32_1, new_be32_1;
        __builtin_memcpy(&old_be32_0, &dv->old_value[0], 4);
        __builtin_memcpy(&new_be32_0, &dv->new_value[0], 4);
        __builtin_memcpy(&old_be32_1, &dv->old_value[4], 4);
        __builtin_memcpy(&new_be32_1, &dv->new_value[4], 4);

        __u32 old_le_0 = bpf_ntohl(old_be32_0);
        __u32 new_le_0 = bpf_ntohl(new_be32_0);
        csum = bpf_csum_diff(&old_le_0, 4, &new_le_0, 4, csum);

        __u32 old_le_1 = bpf_ntohl(old_be32_1);
        __u32 new_le_1 = bpf_ntohl(new_be32_1);
        csum = bpf_csum_diff(&old_le_1, 4, &new_le_1, 4, csum);
        DEBUG_PRINT("  csum_diff: size 8, processed 2x4 bytes\n");
        return csum;
    } else if (dv->size == 16) {
        // 16-byte value (IPv6 address): process as four 4-byte chunks
        __be32 old_be32[4], new_be32[4];
        __builtin_memcpy(&old_be32[0], &dv->old_value[0], 4);
        __builtin_memcpy(&old_be32[1], &dv->old_value[4], 4);
        __builtin_memcpy(&old_be32[2], &dv->old_value[8], 4);
        __builtin_memcpy(&old_be32[3], &dv->old_value[12], 4);
        __builtin_memcpy(&new_be32[0], &dv->new_value[0], 4);
        __builtin_memcpy(&new_be32[1], &dv->new_value[4], 4);
        __builtin_memcpy(&new_be32[2], &dv->new_value[8], 4);
        __builtin_memcpy(&new_be32[3], &dv->new_value[12], 4);

        for (int i = 0; i < 4; i++) {
            __u32 old_le = bpf_ntohl(old_be32[i]);
            __u32 new_le = bpf_ntohl(new_be32[i]);
            csum = bpf_csum_diff(&old_le, 4, &new_le, 4, csum);
        }
        DEBUG_PRINT("  csum_diff: size 16, processed 4x4 bytes\n");
        return csum;
    }

    DEBUG_PRINT("  csum_diff: off=%u sz=%u old=0x%x new=0x%x\n", dv->offset, dv->size, bpf_ntohl(old_u.val), bpf_ntohl(new_u.val));

    // bpf_csum_diff: padding bytes cancel out, only the diff contributes
    csum = bpf_csum_diff(&old_u.val, 4, &new_u.val, 4, csum);
    DEBUG_PRINT("    after csum_diff: csum=0x%llx\n", (unsigned long long)csum);

    return csum;
}

// Apply checksum updates using bpf_csum_diff for each diff value
// Uses old_value and new_value from diff_value struct directly, avoiding map access
// Constructs 4-byte aligned values with padding that cancels out in bpf_csum_diff
// Note: __noinline prevents verifier state explosion when called from unrolled loop
static __noinline int apply_csum_with_bpf_diff(struct xdp_md *ctx, struct checksum_meta *meta, struct diff_value *diffs,
                                               __u8 diff_count, __u16 pkt_len)
{
    // Load current checksum value from packet (base packet was copied, checksum not yet modified)
    __be16 old_csum_be;
    if (bpf_xdp_load_bytes(ctx, meta->csum_offset, &old_csum_be, 2) < 0)
        return -1;
    __u16 old_csum = bpf_ntohs(old_csum_be);

    // UDP checksum of 0 means "no checksum" but is stored as 0xFFFF
    if (old_csum == 0 && (meta->csum_type == CSUM_TYPE_UDP_IPV4 || meta->csum_type == CSUM_TYPE_UDP_IPV6))
        old_csum = 0xFFFF;

    // Initialize seed with inverted checksum (katran-style)
    __wsum csum = ~old_csum & 0xFFFF;

    DEBUG_PRINT("csum_diff: type=%d old_csum=0x%x seed=0x%x diff_count=%d\n", meta->csum_type, old_csum, csum, diff_count);

    // Apply bpf_csum_diff for each diff using values from diff_value struct
    // No variable-offset map access needed
    // NOTE: Do NOT use #pragma unroll here - it causes verifier state explosion
    // The bounded loop (i < MAX_DIFFS_PER_PACKET where MAX=8) is handled by the verifier
    // Each iteration calls __noinline apply_single_csum_diff to isolate branching
    for (int i = 0; i < MAX_DIFFS_PER_PACKET; i++) {
        if (i >= diff_count)
            break;
        csum = apply_single_csum_diff(&diffs[i], meta, pkt_len, csum);
    }

    // Fold and finalize the checksum
    DEBUG_PRINT("csum_diff: final csum=0x%llx\n", (unsigned long long)csum);
    __u16 new_csum = csum_fold_helper(csum);
    DEBUG_PRINT("csum_diff: folded new_csum=0x%x\n", new_csum);

    // UDP checksum of 0 means "no checksum", use 0xFFFF instead per RFC 768
    if (new_csum == 0 && (meta->csum_type == CSUM_TYPE_UDP_IPV4 || meta->csum_type == CSUM_TYPE_UDP_IPV6))
        new_csum = 0xFFFF;

    __be16 new_csum_be = bpf_htons(new_csum);
    if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &new_csum_be, 2) < 0)
        return -1;

    return 0;
}

SEC("xdp")
int xdp_tx(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    // 1. Get per-CPU packet state
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
    if (count > MAX_DIFF_ENTRIES)
        count = MAX_DIFF_ENTRIES;

    __u32 local_idx = state->idx;
    if (local_idx >= count)
        local_idx = 0;

    // 2. Get diff entry for current index (need this first to get base_idx)
    struct diff_entry *diff = bpf_map_lookup_elem(&diff_map, &local_idx);
    if (!diff) {
        DEBUG_PRINT("diff_map lookup failed\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 3. Get base packet using base_idx from diff entry
    __u32 base_idx = diff->base_idx;
    if (base_idx >= MAX_BASE_PACKETS)
        base_idx = 0;
    struct base_packet *base = bpf_map_lookup_elem(&base_packet_map, &base_idx);
    if (!base) {
        DEBUG_PRINT("base_packet_map lookup failed\n");
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
// Require minimum 64 byte packets for chunk-based copy.
#define COPY_CHUNK_SIZE 64

    // Require minimum packet size of 64 bytes
    if (target_len < COPY_CHUNK_SIZE) {
        DEBUG_PRINT("packet too small (min 64 bytes): %u\n", target_len);
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
// Support up to 2048 bytes (32 chunks of 64 bytes) to match MAX_TEMPLATE_SIZE
#define MAX_COPY_CHUNKS 32

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

    // Track diff errors for debugging (looked up later for stats)
    __u8 diff_errors = 0;

    // Intentionally continue on failures
    // Individual diff failures should not abort entire packet transmission.
    // NOTE: Do NOT use #pragma unroll - bounded loop is fine and reduces verifier states
    for (int i = 0; i < MAX_DIFFS_PER_PACKET; i++) {
        if (i >= diff_count)
            break;
        if (apply_diff(ctx, &diff->diffs[i]) < 0) {
            DEBUG_PRINT("apply_diff failed at %d\n", i);
            diff_errors++;
        }
    }

    // Refresh pointers after apply_diff calls (bpf_xdp_store_bytes may invalidate them)
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // Re-establish packet bounds for verifier after pointer refresh
    if (data + target_len > data_end) {
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 8. Store context for tail call and jump to checksum program
    // This splits the verifier work between two programs
    struct tail_call_ctx *tc_ctx = bpf_map_lookup_elem(&tail_call_ctx_map, &zero);
    if (!tc_ctx) {
        DEBUG_PRINT("tail_call_ctx_map lookup failed\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    tc_ctx->base_idx = base_idx;
    tc_ctx->local_idx = local_idx;
    tc_ctx->target_len = target_len;
    tc_ctx->diff_count = diff_count;
    tc_ctx->checksum_count = base->checksum_count;
    tc_ctx->len_changed = diff->len_changed;
    tc_ctx->diff_errors = diff_errors;

    // Tail call to checksum program
    // If tail call fails, fall through to return XDP_ABORTED
    bpf_tail_call(ctx, &xdp_progs, XDP_PROG_CHECKSUM);

    // Tail call failed - this should not happen if prog_array is properly set up
    DEBUG_PRINT("tail call to xdp_tx_checksum failed\n");
    RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
}

// Second part of xdp_tx: checksum processing and stats update
// Called via tail call from xdp_tx to avoid verifier instruction limit
SEC("xdp")
int xdp_tx_checksum(struct xdp_md *ctx)
{
    __u32 zero = 0;

    // 1. Retrieve context from tail call
    struct tail_call_ctx *tc_ctx = bpf_map_lookup_elem(&tail_call_ctx_map, &zero);
    if (!tc_ctx) {
        DEBUG_PRINT("tail_call_ctx_map lookup failed in checksum\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    __u32 base_idx = tc_ctx->base_idx;
    __u32 local_idx = tc_ctx->local_idx;
    __u16 target_len = tc_ctx->target_len;
    __u8 diff_count = tc_ctx->diff_count;
    __u8 checksum_count = tc_ctx->checksum_count;
    __u8 len_changed = tc_ctx->len_changed;
    __u8 diff_errors = tc_ctx->diff_errors;

    // Bounds check
    if (checksum_count > MAX_CHECKSUM_ENTRIES)
        checksum_count = MAX_CHECKSUM_ENTRIES;
    if (base_idx >= MAX_BASE_PACKETS)
        base_idx = 0;

    // 2. Get diff entry for incremental checksum (need diffs array)
    struct diff_entry *diff = bpf_map_lookup_elem(&diff_map, &local_idx);
    if (!diff) {
        DEBUG_PRINT("diff_map lookup failed in checksum\n");
        RETURN_ACTION(ctx, &xdpcap_hook, XDP_ABORTED);
    }

    // 3. Handle checksums - use incremental or full recalculation based on length change
    __u32 csum_base_offset = base_idx * MAX_CHECKSUM_ENTRIES;
    __u8 checksum_errors = 0;

    if (len_changed) {
        // Packet length changed - update IP/UDP length fields first
        if (update_packet_lengths(ctx, target_len) < 0) {
            DEBUG_PRINT("update_packet_lengths failed\n");
            checksum_errors++;
        }

        // Then recalculate checksums from scratch
        for (int i = 0; i < MAX_CHECKSUM_ENTRIES; i++) {
            if (i >= checksum_count)
                break;
            __u32 csum_idx = csum_base_offset + i;
            struct checksum_meta *meta = bpf_map_lookup_elem(&checksum_meta_map, &csum_idx);
            if (!meta) {
                DEBUG_PRINT("checksum_meta_map lookup failed at %d\n", i);
                checksum_errors++;
                break;
            }
            if (recalc_checksum(ctx, meta, target_len) < 0) {
                DEBUG_PRINT("recalc_checksum failed at %d\n", i);
                checksum_errors++;
            }
        }
    } else {
        // Packet length unchanged - use bpf_csum_diff for incremental updates
        for (int i = 0; i < MAX_CHECKSUM_ENTRIES; i++) {
            if (i >= checksum_count)
                break;
            __u32 csum_idx = csum_base_offset + i;
            struct checksum_meta *meta = bpf_map_lookup_elem(&checksum_meta_map, &csum_idx);
            if (!meta) {
                DEBUG_PRINT("checksum_meta_map lookup failed at %d\n", i);
                checksum_errors++;
                break;
            }
            if (apply_csum_with_bpf_diff(ctx, meta, diff->diffs, diff_count, target_len) < 0) {
                DEBUG_PRINT("apply_csum_with_bpf_diff failed at %d\n", i);
                checksum_errors++;
            }
        }
    }

    // 4. Update index (round-robin)
    struct pkt_state *state = bpf_map_lookup_elem(&pkt_state_map, &zero);
    if (state) {
        __u32 count = state->count;
        if (count > MAX_DIFF_ENTRIES)
            count = MAX_DIFF_ENTRIES;
        __u32 next = local_idx + 1;
        if (next >= count)
            next = 0;
        state->idx = next;
    }

    // 5. Update stats
    struct datarec *rec = bpf_map_lookup_elem(&tx_stats_map, &zero);
    if (rec) {
        rec->packets++;
        rec->bytes += target_len;
        if (diff_errors)
            rec->diff_errors += diff_errors;
        if (checksum_errors)
            rec->checksum_errors += checksum_errors;
    }

    DEBUG_PRINT("xdp_tx_checksum: idx=%u len=%u\n", local_idx, target_len);
    RETURN_ACTION(ctx, &xdpcap_hook, XDP_TX);
}
