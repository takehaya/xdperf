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
    __u32 value = dv->new_value;

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

// Recalculate checksum from scratch using bpf_xdp_load_bytes/bpf_xdp_store_bytes
// Used when packet length changes (incremental update not possible)
// This is O(packet_length) - only use when necessary
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
static __always_inline int update_packet_lengths(struct xdp_md *ctx, __u16 target_len)
{
    // Load Ethernet header to check protocol
    struct ethhdr eth;
    if (bpf_xdp_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
        return -1;

    __u16 eth_proto = eth.h_proto;
    __u16 l3_offset = sizeof(struct ethhdr);

    // Handle VLAN (single or double)
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

// Check if a diff affects a particular checksum
static __always_inline bool diff_affects_checksum(struct diff_value *dv, struct checksum_meta *meta, __u16 pkt_len)
{
    __u16 diff_start = dv->offset;
    __u16 diff_end = dv->offset + dv->size;

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

// Apply checksum updates using bpf_csum_diff for each diff value
// Uses old_value and new_value from diff_value struct directly, avoiding map access
// Constructs 4-byte aligned values with padding that cancels out in bpf_csum_diff
static __always_inline int apply_csum_with_bpf_diff(struct xdp_md *ctx, struct checksum_meta *meta, struct diff_value *diffs,
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
#pragma unroll
    for (int i = 0; i < MAX_DIFFS_PER_PACKET; i++) {
        if (i >= diff_count)
            break;

        struct diff_value *dv = &diffs[i];

        // Skip if this diff doesn't affect the checksum
        if (!diff_affects_checksum(dv, meta, pkt_len))
            continue;

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

        // Little-endian checksum calculation (see compile-time check above).
        // csum_partial loads 32-bit values as LE and folds: fold(0xAABBCCDD) = 0xCCDD + 0xAABB
        // Byte placement for correct checksum contribution:
        // - High byte (even offset): bytes[3] → folds to 0xVV00
        // - Low byte (odd offset): bytes[0] → folds to 0x00VV
        // - 2-byte: 16-bit LE at bytes[0:1]
        // - 4-byte: store directly
        if (dv->size == 1) {
            if (word_pos == 0) {
                // Even offset = high byte of 16-bit word
                // On LE: bytes[3] maps to high16 bits, folds to 0xVV00
                old_u.bytes[3] = (__u8)dv->old_value;
                new_u.bytes[3] = (__u8)dv->new_value;
            } else {
                // Odd offset = low byte of 16-bit word
                // On LE: bytes[0] maps to low16 bits, folds to 0x00VV
                old_u.bytes[0] = (__u8)dv->old_value;
                new_u.bytes[0] = (__u8)dv->new_value;
            }
        } else if (dv->size == 2) {
            // 2-byte value: store as 16-bit LE at bytes[0:1]
            // Value 0x04D2 → memory [D2, 04, 00, 00] → folds to 0x04D2
            old_u.bytes[0] = (__u8)(dv->old_value & 0xFF);
            old_u.bytes[1] = (__u8)(dv->old_value >> 8);
            new_u.bytes[0] = (__u8)(dv->new_value & 0xFF);
            new_u.bytes[1] = (__u8)(dv->new_value >> 8);
        } else if (dv->size == 4) {
            // 4-byte value: store directly without byte swap
            // Fold gives same sum regardless of byte order (commutative)
            old_u.val = dv->old_value;
            new_u.val = dv->new_value;
        }

        DEBUG_PRINT("  diff[%d]: off=%u sz=%u old=0x%x new=0x%x\n", i, dv->offset, dv->size, bpf_ntohl(old_u.val),
                    bpf_ntohl(new_u.val));

        // bpf_csum_diff: padding bytes cancel out, only the diff contributes
        csum = bpf_csum_diff(&old_u.val, 4, &new_u.val, 4, csum);
        DEBUG_PRINT("    after csum_diff: csum=0x%llx\n", (unsigned long long)csum);
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

        // Intentionally continue on failures
        // Individual diff failures should not abort entire packet transmission.
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

    // 8. Handle checksums - use incremental or full recalculation based on length change
    __u8 checksum_count = base->checksum_count;
    if (checksum_count > MAX_CHECKSUM_ENTRIES)
        checksum_count = MAX_CHECKSUM_ENTRIES;

    // Checksum key offset for this base: base_idx * MAX_CHECKSUM_ENTRIES
    __u32 csum_base_offset = base_idx * MAX_CHECKSUM_ENTRIES;

    // Intentionally continue on checksum failures: performance-critical path.
    // Partial checksum errors should not abort packet transmission.
    if (diff->len_changed) {
        // Packet length changed - update IP/UDP length fields first
        if (update_packet_lengths(ctx, target_len) < 0) {
            DEBUG_PRINT("update_packet_lengths failed\n");
        }

        // Then recalculate checksums from scratch
        // This is O(packet_length) but only happens when length varies
#pragma unroll
        for (int i = 0; i < MAX_CHECKSUM_ENTRIES; i++) {
            if (i >= checksum_count)
                break;
            __u32 csum_idx = csum_base_offset + i;
            struct checksum_meta *meta = bpf_map_lookup_elem(&checksum_meta_map, &csum_idx);
            if (!meta)
                break;
            if (recalc_checksum(ctx, meta, target_len) < 0) {
                DEBUG_PRINT("recalc_checksum failed at %d\n", i);
            }
        }
    } else {
        // Packet length unchanged - use bpf_csum_diff for incremental updates
        // Uses katran-style approach with actual 4-byte aligned packet data
#pragma unroll
        for (int i = 0; i < MAX_CHECKSUM_ENTRIES; i++) {
            if (i >= checksum_count)
                break;
            __u32 csum_idx = csum_base_offset + i;
            struct checksum_meta *meta = bpf_map_lookup_elem(&checksum_meta_map, &csum_idx);
            if (!meta)
                break;
            if (apply_csum_with_bpf_diff(ctx, meta, diff->diffs, diff_count, target_len) < 0) {
                DEBUG_PRINT("apply_csum_with_bpf_diff failed at %d\n", i);
            }
        }
    }

    // 9. Update index (round-robin)
    __u32 next = local_idx + 1;
    if (next >= count)
        next = 0;
    state->idx = next;

    // 10. Update stats
    struct datarec *rec = bpf_map_lookup_elem(&tx_stats_map, &zero);
    if (rec) {
        rec->packets++;
        rec->bytes += target_len;
    }

    DEBUG_PRINT("xdp_tx: cnt=%u idx=%u len=%u\n", count, local_idx, target_len);
    RETURN_ACTION(ctx, &xdpcap_hook, XDP_TX);
}
