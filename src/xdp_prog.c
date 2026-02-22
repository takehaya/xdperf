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
#include <stddef.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

// Minimum packet size for chunk-based copy (must be >= 64 for verifier bounds)
#define COPY_CHUNK_SIZE 64

// Expose COPY_CHUNK_SIZE to Go via spec.Variables
volatile __u32 min_packet_size = COPY_CHUNK_SIZE;

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

// Check if size is a supported diff size for bpf_xdp_store_bytes
// Supported sizes: 1, 2, 4, 6, 8 bytes
static __always_inline bool is_supported_diff_size(__u8 size)
{
    switch (size) {
    case 1:
    case 2:
    case 4:
    case 6:
    case 8:
        return true;
    default:
        return false;
    }
}

// Apply a single diff value to the packet
// Uses bpf_xdp_store_bytes() to avoid verifier issues with variable-offset writes
// new_value is stored in big-endian (network byte order)
// Note: __noinline prevents verifier state explosion when called from unrolled loop
static __noinline bool apply_diff(struct xdp_md *ctx, struct diff_value *dv)
{
    if (dv->size == 0 || dv->offset == 0xFFFF)
        return true; // Skip empty diff

    if (!is_supported_diff_size(dv->size))
        return false;

    return bpf_xdp_store_bytes(ctx, dv->offset, dv->new_value, dv->size) >= 0;
}

// Ensure IPPROTO_ETHERNET is defined (not present in older kernel headers)
#ifndef IPPROTO_ETHERNET
#define IPPROTO_ETHERNET 143
#endif

// Helper: Traverse IPv6 extension headers to find transport layer
// Returns true if transport layer found, outputs protocol and L4 offset
// If final_dst is non-NULL and SRH is found, copies the final destination (segment[LastEntry]) to it
// Supports: Hop-by-Hop (0), Routing (43), Fragment (44), Destination Options (60)
// Also recognizes IPPROTO_ETHERNET (143), IPPROTO_IPIP (4), IPPROTO_IPV6 (41) as terminal protocols
static __always_inline bool ipv6_find_transport(struct xdp_md *ctx, __u16 l3_offset, __u8 *out_proto, __u16 *out_l4_offset,
                                                __u8 *final_dst, bool *has_final_dst)
{
    __u8 proto;
    if (bpf_xdp_load_bytes(ctx, l3_offset + 6, &proto, 1) < 0)
        return false;

    __u16 l4_offset = l3_offset + sizeof(struct ipv6hdr); // 40 bytes

#pragma unroll
    for (int i = 0; i < 4; i++) { // Max 4 extension headers
        if (proto == IPPROTO_UDP || proto == IPPROTO_TCP || proto == IPPROTO_ICMPV6 || proto == IPPROTO_ETHERNET ||
            proto == IPPROTO_IPIP || proto == IPPROTO_IPV6) {
            *out_proto = proto;
            *out_l4_offset = l4_offset;
            return true;
        }

        if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_DSTOPTS) {
            // Extension header: byte 0 = next header, byte 1 = length in 8-octet units (excluding first 8)
            __u8 ext_hdr[2];
            if (bpf_xdp_load_bytes(ctx, l4_offset, ext_hdr, 2) < 0)
                return false;
            proto = ext_hdr[0];
            l4_offset += (ext_hdr[1] + 1) * 8;
        } else if (proto == IPPROTO_ROUTING) {
            // Routing header (SRH): extract final destination for pseudo-header
            // SRH structure: next_hdr(1) + hdr_ext_len(1) + routing_type(1) + segments_left(1)
            //                + last_entry(1) + flags(1) + tag(2) + segment_list[...]
            // Per RFC 8200, when Segments Left > 0, use final destination from SRH
            // When Segments Left = 0, use IPv6 Dst (packet has reached final destination)
            __u8 srh_hdr[5]; // next_hdr, hdr_ext_len, routing_type, segments_left, last_entry
            if (bpf_xdp_load_bytes(ctx, l4_offset, srh_hdr, 5) < 0)
                return false;

            __u8 segments_left = srh_hdr[3];
            __u8 last_entry = srh_hdr[4];

            // Only use SRH final destination if Segments Left > 0
            if (final_dst && has_final_dst && segments_left > 0) {
                // segment[LastEntry] is at SRH + 8 + LastEntry * 16
                // Segments are stored in reverse order: segment[0] is last hop
                __u16 seg_offset = l4_offset + 8 + (__u16)last_entry * 16;
                if (bpf_xdp_load_bytes(ctx, seg_offset, final_dst, 16) < 0)
                    return false;
                *has_final_dst = true;
            }

            proto = srh_hdr[0];
            l4_offset += (srh_hdr[1] + 1) * 8;
        } else if (proto == IPPROTO_FRAGMENT) {
            // Fragment header is fixed 8 bytes
            __u8 next_hdr;
            if (bpf_xdp_load_bytes(ctx, l4_offset, &next_hdr, 1) < 0)
                return false;
            proto = next_hdr;
            l4_offset += 8;
        } else {
            return false; // Unknown extension header or no transport found
        }
    }
    return false; // Too many extension headers
}

// Recalculate checksum from scratch using bpf_xdp_load_bytes/bpf_xdp_store_bytes
// Used when packet length changes (incremental update not possible)
// This is O(packet_length) - only use when necessary
// Auto-detects checksum type from packet content:
// - IPv4 header checksum: csum_offset == ip_header_offset + offsetof(struct iphdr, check)
// - Transport checksum: determined by IP protocol field
// Note: __noinline prevents verifier state explosion when called from loops
static __noinline bool recalc_checksum(struct xdp_md *ctx, struct checksum_meta *meta, __u16 pkt_len)
{
    __u16 csum;
    __u16 transport_len;

    // First load IP version to determine checksum type
    __u8 version_byte;
    if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset, &version_byte, 1) < 0)
        return false;

    __u8 ip_version = (version_byte >> 4) & 0x0F;

    if (ip_version == 4) {
        // Load IPv4 header
        struct iphdr iph;
        if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset, &iph, sizeof(iph)) < 0)
            return false;

        // Check if this is IPv4 header checksum
        // IPv4 header checksum is at ip_header_offset + offsetof(struct iphdr, check)
        if (meta->csum_offset == meta->ip_header_offset + offsetof(struct iphdr, check)) {
            csum = calc_ipv4_header_csum(ctx, meta->ip_header_offset, iph.ihl * 4, IPV4_CSUM_OFFSET);
            if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
                return false;
            return true;
        }
        // IPv4 transport checksum
        transport_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4);

        // ICMP uses simple checksum (no pseudo-header), others use pseudo-header
        if (iph.protocol == IPPROTO_ICMP) {
            csum = calc_ipv4_header_csum(ctx, meta->header_start, transport_len, ICMPV4_CSUM_OFFSET);
        } else {
            csum = calc_transport_csum_ipv4(ctx, meta->ip_header_offset, meta->header_start, transport_len, iph.protocol);
        }
        if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
            return false;
    } else if (ip_version == 6) {
        // IPv6 transport checksum (supports extension headers like SRH)
        __u8 proto;
        __u16 l4_offset;
        __u8 final_dst[16] = {0};
        bool has_final_dst = false;
        if (!ipv6_find_transport(ctx, meta->ip_header_offset, &proto, &l4_offset, final_dst, &has_final_dst))
            return false; // No transport layer found

        // Use computed l4_offset for both length calculation and data reading
        transport_len = pkt_len - l4_offset;

        __u8 *final_dst_ptr = has_final_dst ? final_dst : NULL;
        csum = calc_transport_csum_ipv6(ctx, meta->ip_header_offset, l4_offset, transport_len, proto, final_dst_ptr);
        if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &csum, 2) < 0)
            return false;
    } else {
        // Unknown IP version
        return false;
    }

    return true;
}

// Update IP and transport layer length fields when packet length changed
// Must be called after base packet copy, before checksum recalculation
// Note: __noinline prevents verifier state explosion
static __noinline bool update_packet_lengths(struct xdp_md *ctx, __u16 target_len)
{
    // Load Ethernet header to check protocol
    struct ethhdr eth;
    if (bpf_xdp_load_bytes(ctx, 0, &eth, sizeof(eth)) < 0)
        return false;

    __u16 eth_proto = eth.h_proto;
    __u16 l3_offset = sizeof(struct ethhdr);

    // Handle VLAN (single or double).
    // Note: Triple-tagged packets are not supported.
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        __be16 vlan_proto;
        if (bpf_xdp_load_bytes(ctx, l3_offset + 2, &vlan_proto, 2) < 0)
            return false;
        eth_proto = vlan_proto;
        l3_offset += 4;

        // Double VLAN (QinQ)
        if (eth_proto == bpf_htons(ETH_P_8021Q)) {
            if (bpf_xdp_load_bytes(ctx, l3_offset + 2, &vlan_proto, 2) < 0)
                return false;
            eth_proto = vlan_proto;
            l3_offset += 4;
        }
    }

    // Handle MPLS - skip labels until S=1 (bottom of stack)
    // MPLS header: Label(20) | Exp(3) | S(1) | TTL(8) = 4 bytes
    // S bit is at byte offset 2, bit 0 (0x01)
    if (eth_proto == bpf_htons(ETH_P_MPLS_UC) || eth_proto == bpf_htons(ETH_P_MPLS_MC)) {
#pragma unroll
        for (int i = 0; i < 8; i++) { // Max 8 MPLS labels
            __u8 mpls_byte2;
            if (bpf_xdp_load_bytes(ctx, l3_offset + 2, &mpls_byte2, 1) < 0)
                return false;
            l3_offset += 4;        // Skip this MPLS label
            if (mpls_byte2 & 0x01) // S bit set = bottom of stack
                break;
        }
        // After MPLS, detect inner protocol from first nibble (IPv4=4, IPv6=6)
        __u8 version_byte;
        if (bpf_xdp_load_bytes(ctx, l3_offset, &version_byte, 1) < 0)
            return false;
        __u8 ip_version = (version_byte >> 4) & 0x0F;
        if (ip_version == 4)
            eth_proto = bpf_htons(ETH_P_IP);
        else if (ip_version == 6)
            eth_proto = bpf_htons(ETH_P_IPV6);
        else {
            // L2VPN: inner Ethernet frame after MPLS labels
            // TODO: PW Control Word (RFC 4385) not supported - if present (first nibble 0),
            //       4 bytes should be skipped before the inner Ethernet header
            // Skip inner Ethernet header (14 bytes) and read inner EtherType
            __be16 inner_eth_proto;
            if (bpf_xdp_load_bytes(ctx, l3_offset + 12, &inner_eth_proto, 2) < 0)
                return false;
            l3_offset += 14;
            eth_proto = inner_eth_proto;
        }
    }

    // Validate l3_offset after VLAN/MPLS parsing
    if (l3_offset >= target_len)
        return false;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        // IPv4: update tot_len (offset 2 from IP header)
        __u16 ip_len = target_len - l3_offset;
        __be16 ip_len_be = bpf_htons(ip_len);
        if (bpf_xdp_store_bytes(ctx, l3_offset + 2, &ip_len_be, 2) < 0)
            return false;

        // Get protocol from IP header (offset 9)
        __u8 proto;
        if (bpf_xdp_load_bytes(ctx, l3_offset + 9, &proto, 1) < 0)
            return false;

        // Get IHL (IP Header Length) from first byte
        __u8 version_ihl;
        if (bpf_xdp_load_bytes(ctx, l3_offset, &version_ihl, 1) < 0)
            return false;
        __u16 ihl = (version_ihl & 0x0F) * 4;
        __u16 l4_offset = l3_offset + ihl;

        if (proto == IPPROTO_UDP) {
            // UDP: update len field (offset 4 from UDP header)
            if (target_len < l4_offset)
                return false;
            __u16 udp_len = target_len - l4_offset;
            __be16 udp_len_be = bpf_htons(udp_len);
            if (bpf_xdp_store_bytes(ctx, l4_offset + 4, &udp_len_be, 2) < 0)
                return false;
        }
        // TCP doesn't have a length field in header
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6: update payload_len (offset 4 from IPv6 header)
        if (target_len < l3_offset + sizeof(struct ipv6hdr))
            return false;
        __u16 payload_len = target_len - l3_offset - sizeof(struct ipv6hdr);
        __be16 payload_len_be = bpf_htons(payload_len);
        if (bpf_xdp_store_bytes(ctx, l3_offset + 4, &payload_len_be, 2) < 0)
            return false;

        // Find transport layer (traversing extension headers like SRH)
        __u8 proto;
        __u16 l4_offset;
        if (!ipv6_find_transport(ctx, l3_offset, &proto, &l4_offset, NULL, NULL))
            return true; // No transport layer found, but payload_len is updated

        if (proto == IPPROTO_UDP) {
            // UDP: update len field
            if (target_len < l4_offset)
                return false;
            __u16 udp_len = target_len - l4_offset;
            __be16 udp_len_be = bpf_htons(udp_len);
            if (bpf_xdp_store_bytes(ctx, l4_offset + 4, &udp_len_be, 2) < 0)
                return false;
        } else if (proto == IPPROTO_ETHERNET) {
            // L2VPN over SRv6: inner Ethernet frame after SRH
            // Skip inner Ethernet header (14 bytes) and read inner EtherType
            __be16 inner_eth_proto;
            if (bpf_xdp_load_bytes(ctx, l4_offset + 12, &inner_eth_proto, 2) < 0)
                return true;
            __u16 inner_l3 = l4_offset + 14;

            if (inner_eth_proto == bpf_htons(ETH_P_IP) && target_len > inner_l3) {
                // Update inner IPv4 tot_len
                __u16 inner_ip_len = target_len - inner_l3;
                __be16 inner_ip_len_be = bpf_htons(inner_ip_len);
                if (bpf_xdp_store_bytes(ctx, inner_l3 + 2, &inner_ip_len_be, 2) < 0)
                    return false;
                // Read IHL and protocol from inner IPv4 header
                __u8 inner_ver_ihl;
                if (bpf_xdp_load_bytes(ctx, inner_l3, &inner_ver_ihl, 1) < 0)
                    return false;
                __u16 inner_ihl = (inner_ver_ihl & 0x0F) * 4;
                __u8 inner_proto;
                if (bpf_xdp_load_bytes(ctx, inner_l3 + 9, &inner_proto, 1) < 0)
                    return false;
                __u16 inner_l4 = inner_l3 + inner_ihl;
                if (inner_proto == IPPROTO_UDP && target_len > inner_l4) {
                    __u16 inner_udp_len = target_len - inner_l4;
                    __be16 inner_udp_len_be = bpf_htons(inner_udp_len);
                    if (bpf_xdp_store_bytes(ctx, inner_l4 + 4, &inner_udp_len_be, 2) < 0)
                        return false;
                }
            } else if (inner_eth_proto == bpf_htons(ETH_P_IPV6) && target_len > inner_l3 + sizeof(struct ipv6hdr)) {
                // Update inner IPv6 payload_len
                __u16 inner_payload_len = target_len - inner_l3 - sizeof(struct ipv6hdr);
                __be16 inner_payload_len_be = bpf_htons(inner_payload_len);
                if (bpf_xdp_store_bytes(ctx, inner_l3 + 4, &inner_payload_len_be, 2) < 0)
                    return false;
            }
        } else if (proto == IPPROTO_IPIP) {
            // L3VPN over SRv6: inner IPv4 after SRH
            if (target_len > l4_offset) {
                __u16 inner_ip_len = target_len - l4_offset;
                __be16 inner_ip_len_be = bpf_htons(inner_ip_len);
                if (bpf_xdp_store_bytes(ctx, l4_offset + 2, &inner_ip_len_be, 2) < 0)
                    return false;
                // Read IHL and protocol from inner IPv4 header
                __u8 inner_ver_ihl;
                if (bpf_xdp_load_bytes(ctx, l4_offset, &inner_ver_ihl, 1) < 0)
                    return false;
                __u16 inner_ihl = (inner_ver_ihl & 0x0F) * 4;
                __u8 inner_proto;
                if (bpf_xdp_load_bytes(ctx, l4_offset + 9, &inner_proto, 1) < 0)
                    return false;
                __u16 inner_l4 = l4_offset + inner_ihl;
                if (inner_proto == IPPROTO_UDP && target_len > inner_l4) {
                    __u16 inner_udp_len = target_len - inner_l4;
                    __be16 inner_udp_len_be = bpf_htons(inner_udp_len);
                    if (bpf_xdp_store_bytes(ctx, inner_l4 + 4, &inner_udp_len_be, 2) < 0)
                        return false;
                }
            }
        } else if (proto == IPPROTO_IPV6) {
            // L3VPN over SRv6: inner IPv6 after SRH
            if (target_len > l4_offset + sizeof(struct ipv6hdr)) {
                __u16 inner_payload_len = target_len - l4_offset - sizeof(struct ipv6hdr);
                __be16 inner_payload_len_be = bpf_htons(inner_payload_len);
                if (bpf_xdp_store_bytes(ctx, l4_offset + 4, &inner_payload_len_be, 2) < 0)
                    return false;
            }
        }
    }

    return true;
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
// This is guaranteed because valid packet offsets are < 2048 (MAX_PACKET_SIZE)
// and size is at most 8 bytes.
// Auto-detects checksum type (IPv4 header vs transport) from packet content.
// Note: __noinline prevents verifier state explosion when called from loops
static __noinline bool diff_affects_checksum(struct xdp_md *ctx, struct diff_value *dv, struct checksum_meta *meta, __u16 pkt_len)
{
    __u16 diff_start = dv->offset;
    __u16 diff_end = dv->offset + dv->size; // Safe: offset < 2048, size <= 8

    // First load IP version to determine checksum type
    __u8 version_byte;
    if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset, &version_byte, 1) < 0)
        // Cannot read IP header version, so we cannot reliably exclude checksum impact.
        // Conservatively return true to ensure checksum is recalculated.
        return true;

    __u8 ip_version = (version_byte >> 4) & 0x0F;

    if (ip_version == 4) {
        // Check if this is IPv4 header checksum
        if (meta->csum_offset == meta->ip_header_offset + offsetof(struct iphdr, check)) {
            // IPv4 header checksum covers [ip_offset, ip_offset + sizeof(struct iphdr))
            __u16 ip_start = meta->ip_header_offset;
            __u16 ip_end = ip_start + sizeof(struct iphdr);
            return diff_start < ip_end && diff_end > ip_start;
        }

        // Get protocol to check if ICMP
        __u8 proto;
        if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset + 9, &proto, 1) < 0)
            return true; // Conservative: assume affects

        // ICMP doesn't use pseudo-header, so IP address changes don't affect ICMP checksum
        if (proto != IPPROTO_ICMP) {
            // IPv4 transport (TCP/UDP): Pseudo-header includes src IP at ip_offset+12, dst IP at ip_offset+16
            __u16 src_ip = meta->ip_header_offset + offsetof(struct iphdr, saddr);
            __u16 dst_ip_end = meta->ip_header_offset + sizeof(struct iphdr);
            if (diff_start < dst_ip_end && diff_end > src_ip)
                return true;
        }
    } else if (ip_version == 6) {
        // IPv6: Pseudo-header includes src/dst addresses at ip_offset+8 to ip_offset+40
        __u16 src_ip = meta->ip_header_offset + offsetof(struct ipv6hdr, saddr);
        __u16 dst_ip_end = meta->ip_header_offset + sizeof(struct ipv6hdr);
        if (diff_start < dst_ip_end && diff_end > src_ip)
            return true;
    }

    // Transport layer data
    return diff_start < pkt_len && diff_end > meta->header_start;
}

// Process a single diff for checksum update
// Supported sizes: 1, 2, 4, 6, 8 bytes (validated in apply_diff)
// Offset parity matters: checksum is computed over 16-bit words, so byte position affects calculation
static __noinline __wsum apply_single_csum_diff(struct xdp_md *ctx, struct diff_value *dv, struct checksum_meta *meta,
                                                __u16 pkt_len, __wsum csum)
{
    // Skip if this diff doesn't affect the checksum
    if (!diff_affects_checksum(ctx, dv, meta, pkt_len))
        return csum;

    bool odd_offset = dv->offset & 1;

    // Size 4: ABCD
    // Even offset: ABCD (4 bytes)
    // Odd offset:  0ABCD000 (8 bytes, single call)
    if (dv->size == 4) {
        if (odd_offset) {
            __u8 old_buf[8] = {0};
            __u8 new_buf[8] = {0};
            __builtin_memcpy(&old_buf[1], dv->old_value, 4);
            __builtin_memcpy(&new_buf[1], dv->new_value, 4);
            csum = bpf_csum_diff((__be32 *)old_buf, 8, (__be32 *)new_buf, 8, csum);
        } else {
            csum = bpf_csum_diff((__be32 *)dv->old_value, 4, (__be32 *)dv->new_value, 4, csum);
        }
        DEBUG_PRINT("  csum_diff: size 4, odd=%d\n", odd_offset);
        return csum;
    }

    // Size 6: ABCDEF
    // Even offset: ABCDEF00 (8 bytes)
    // Odd offset:  0ABCDEF0 (8 bytes)
    if (dv->size == 6) {
        __u8 old_buf[8] = {0};
        __u8 new_buf[8] = {0};
        if (odd_offset) {
            __builtin_memcpy(&old_buf[1], dv->old_value, 6);
            __builtin_memcpy(&new_buf[1], dv->new_value, 6);
        } else {
            __builtin_memcpy(old_buf, dv->old_value, 6);
            __builtin_memcpy(new_buf, dv->new_value, 6);
        }
        csum = bpf_csum_diff((__be32 *)old_buf, 8, (__be32 *)new_buf, 8, csum);
        DEBUG_PRINT("  csum_diff: size 6, odd=%d\n", odd_offset);
        return csum;
    }

    // Size 8: ABCDEFGH
    // Even offset: ABCDEFGH (8 bytes)
    // Odd offset:  0ABCDEFGH000 (12 bytes, single call)
    if (dv->size == 8) {
        if (odd_offset) {
            __u8 old_buf[12] = {0};
            __u8 new_buf[12] = {0};
            __builtin_memcpy(&old_buf[1], dv->old_value, 8);
            __builtin_memcpy(&new_buf[1], dv->new_value, 8);
            csum = bpf_csum_diff((__be32 *)old_buf, 12, (__be32 *)new_buf, 12, csum);
        } else {
            csum = bpf_csum_diff((__be32 *)dv->old_value, 8, (__be32 *)dv->new_value, 8, csum);
        }
        DEBUG_PRINT("  csum_diff: size 8, odd=%d\n", odd_offset);
        return csum;
    }

    // For sizes 1 and 2, pad to 4 bytes
    // Position within 16-bit word matters for checksum calculation
    __u8 old_padded[4] = {0};
    __u8 new_padded[4] = {0};

    if (dv->size == 1) {
        // Position based on offset parity (network byte order: even=high, odd=low)
        if (odd_offset) {
            // Odd offset: low byte of 16-bit word
            old_padded[1] = dv->old_value[0];
            new_padded[1] = dv->new_value[0];
        } else {
            // Even offset: high byte of 16-bit word
            old_padded[0] = dv->old_value[0];
            new_padded[0] = dv->new_value[0];
        }
    } else if (dv->size == 2) {
        if (odd_offset) {
            // Odd offset: bytes span two 16-bit words (pos 1-2)
            __builtin_memcpy(&old_padded[1], dv->old_value, 2);
            __builtin_memcpy(&new_padded[1], dv->new_value, 2);
        } else {
            // Aligned: copy directly (pos 0-1)
            __builtin_memcpy(old_padded, dv->old_value, 2);
            __builtin_memcpy(new_padded, dv->new_value, 2);
        }
    }

    DEBUG_PRINT("  csum_diff: off=%u sz=%u odd=%d\n", dv->offset, dv->size, odd_offset);
    csum = bpf_csum_diff((__be32 *)old_padded, 4, (__be32 *)new_padded, 4, csum);

    return csum;
}

// Apply checksum updates using bpf_csum_diff for each diff value
// Uses old_value and new_value from diff_value struct directly, avoiding map access
// Constructs 4-byte aligned values with zero padding that doesn't affect the checksum result
// Note: __noinline prevents verifier state explosion when called from unrolled loop
static __noinline bool apply_csum_with_bpf_diff(struct xdp_md *ctx, struct checksum_meta *meta, struct diff_value *diffs,
                                                __u8 diff_count, __u16 pkt_len)
{
    // Load current checksum value from packet (base packet was copied, checksum not yet modified)
    // No byte order conversion - values are in network byte order as read from packet
    __u16 old_csum;
    if (bpf_xdp_load_bytes(ctx, meta->csum_offset, &old_csum, 2) < 0)
        return false;

    // Detect if this is a UDP checksum for special handling of 0 value
    // UDP checksum of 0 means "no checksum" but is stored as 0xFFFF per RFC 768
    bool is_udp = false;
    if (meta->csum_offset != meta->ip_header_offset + offsetof(struct iphdr, check)) {
        // Not IPv4 header checksum, check if UDP
        __u8 version_byte;
        if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset, &version_byte, 1) == 0) {
            __u8 ip_version = (version_byte >> 4) & 0x0F;
            if (ip_version == 4) {
                __u8 proto;
                if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset + 9, &proto, 1) == 0)
                    is_udp = (proto == IPPROTO_UDP);
            } else if (ip_version == 6) {
                // TODO: Extension headers not supported
                __u8 nexthdr;
                if (bpf_xdp_load_bytes(ctx, meta->ip_header_offset + 6, &nexthdr, 1) == 0)
                    is_udp = (nexthdr == IPPROTO_UDP);
            }
        }
    }

    if (old_csum == 0 && is_udp)
        old_csum = 0xFFFF;

    // Initialize seed with inverted checksum (katran-style)
    __wsum csum = ~old_csum & 0xFFFF;

    DEBUG_PRINT("csum_diff: old_csum=0x%x seed=0x%x diff_count=%d is_udp=%d\n", old_csum, csum, diff_count, is_udp);

    // Apply bpf_csum_diff for each diff using values from diff_value struct
    // No variable-offset map access needed
    // NOTE: Do NOT use #pragma unroll here - it causes verifier state explosion
    // The bounded loop (i < MAX_DIFFS_PER_PACKET where MAX=8) is handled by the verifier
    // Each iteration calls __noinline apply_single_csum_diff to isolate branching
    for (int i = 0; i < MAX_DIFFS_PER_PACKET; i++) {
        if (i >= diff_count)
            break;
        csum = apply_single_csum_diff(ctx, &diffs[i], meta, pkt_len, csum);
    }

    // Fold and finalize the checksum
    DEBUG_PRINT("csum_diff: final csum=0x%llx\n", (unsigned long long)csum);
    __u16 new_csum = csum_fold_helper(csum);
    DEBUG_PRINT("csum_diff: folded new_csum=0x%x\n", new_csum);

    // UDP checksum of 0 means "no checksum", use 0xFFFF instead per RFC 768
    if (new_csum == 0 && is_udp)
        new_csum = 0xFFFF;

    // No byte order conversion - checksum stored in network byte order as read from packet
    if (bpf_xdp_store_bytes(ctx, meta->csum_offset, &new_csum, 2) < 0)
        return false;

    return true;
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
    if (target_len > MAX_PACKET_SIZE)
        target_len = MAX_PACKET_SIZE;
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
    // Require minimum COPY_CHUNK_SIZE byte packets for chunk-based copy.

    // Require minimum packet size
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
// Support up to 2048 bytes (32 chunks of 64 bytes) to match MAX_PACKET_SIZE
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

    // 7. Apply diffs (bounded loop for max 8 diffs)
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
        if (!apply_diff(ctx, &diff->diffs[i])) {
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
        if (!update_packet_lengths(ctx, target_len)) {
            DEBUG_PRINT("update_packet_lengths failed\n");
            checksum_errors++;
        }

        // Then recalculate checksums from scratch
        // Error handling strategy:
        // - meta lookup fail: break (map issue, subsequent lookups likely fail too)
        // - recalc fail: continue (only affects this checksum, others may succeed)
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
            if (!recalc_checksum(ctx, meta, target_len)) {
                DEBUG_PRINT("recalc_checksum failed at %d\n", i);
                checksum_errors++;
            }
        }
    } else {
        // Packet length unchanged - use bpf_csum_diff for incremental updates
        // Same error handling strategy as above
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
            if (!apply_csum_with_bpf_diff(ctx, meta, diff->diffs, diff_count, target_len)) {
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
