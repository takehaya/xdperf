#ifndef XDP_CHECKSUM_H
#define XDP_CHECKSUM_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "xdp_prog.h" // For DEBUG_PRINT

// Checksum field offset from transport header start
// UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = checksum at offset 6
// TCP header: src_port(2) + dst_port(2) + seq(4) + ack(4) + data_off/flags(2) + checksum(2) = checksum at offset 16
// ICMPv6 header: type(1) + code(1) + checksum(2) = checksum at offset 2
#define IPV4_CSUM_OFFSET 10
#define UDP_CSUM_OFFSET 6
#define TCP_CSUM_OFFSET 16
#define ICMPV6_CSUM_OFFSET 2
#define ICMPV4_CSUM_OFFSET 2

// Fold 32-bit checksum to 16-bit
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

// Safe transport checksum callback context using bpf_xdp_load_bytes
struct csum_safe_ctx {
    struct xdp_md *ctx;
    __u32 offset;
    __u32 sum;
};

// Safe callback for bpf_loop transport checksum using bpf_xdp_load_bytes
static long csum_safe_callback(__u32 idx, void *vctx)
{
    struct csum_safe_ctx *c = vctx;
    __u32 byte_offset = c->offset + idx * 2;
    __be16 val;

    if (bpf_xdp_load_bytes(c->ctx, byte_offset, &val, 2) < 0)
        return 1; // Stop iteration

    c->sum += bpf_ntohs(val);
    return 0;
}

// Calculate checksum over data without pseudo-header (RFC 1071)
// Used for IPv4 header, ICMPv4, etc.
// Clears the checksum field at csum_field_offset before calculation
static __always_inline __u16 calc_ipv4_header_csum(struct xdp_md *ctx, __u16 data_offset, __u16 data_len, __u16 csum_field_offset)
{
    // Clear checksum field first
    __be16 zero_csum = 0;
    if (bpf_xdp_store_bytes(ctx, data_offset + csum_field_offset, &zero_csum, 2) < 0) {
        DEBUG_PRINT("calc_ipv4_header_csum: failed to clear checksum at offset %u\n", data_offset + csum_field_offset);
        return 0;
    }

    // Sum data using bpf_loop with safe callback
    struct csum_safe_ctx sctx = {
        .ctx = ctx,
        .offset = data_offset,
        .sum = 0,
    };

    __u32 full_pairs = data_len / 2;
    bpf_loop(full_pairs, csum_safe_callback, &sctx, 0);

    __u32 sum = sctx.sum;

    // Handle odd byte
    if (data_len & 1) {
        __u8 odd_byte;
        if (bpf_xdp_load_bytes(ctx, data_offset + data_len - 1, &odd_byte, 1) == 0) {
            sum += odd_byte << 8;
        }
    }

    return bpf_htons(csum_fold(sum));
}

// Calculate transport layer checksum (UDP/TCP) over IPv4
static __always_inline __u16 calc_transport_csum_ipv4(struct xdp_md *ctx, __u16 ip_offset, __u16 transport_offset,
                                                      __u16 transport_len, __u8 protocol)
{
    struct iphdr iph;

    // Load IP header using helper
    if (bpf_xdp_load_bytes(ctx, ip_offset, &iph, sizeof(iph)) < 0) {
        DEBUG_PRINT("calc_transport_csum_ipv4: failed to load IP header at offset %u\n", ip_offset);
        return 0;
    }

    __u32 sum = 0;

    // Pseudo-header
    __u32 saddr = bpf_ntohl(iph.saddr);
    __u32 daddr = bpf_ntohl(iph.daddr);

    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += protocol;
    sum += transport_len;

    // Clear checksum field in packet using helper
    __be16 zero_csum = 0;
    __u16 csum_field_offset = (protocol == IPPROTO_UDP) ? UDP_CSUM_OFFSET : TCP_CSUM_OFFSET;
    if (bpf_xdp_store_bytes(ctx, transport_offset + csum_field_offset, &zero_csum, 2) < 0) {
        DEBUG_PRINT("calc_transport_csum_ipv4: failed to clear checksum at offset %u\n", transport_offset + csum_field_offset);
        return 0;
    }

    // Sum transport header + payload using bpf_loop with safe callback
    // Only iterate over complete 2-byte pairs to avoid read failures at odd lengths
    struct csum_safe_ctx sctx = {
        .ctx = ctx,
        .offset = transport_offset,
        .sum = 0,
    };

    __u32 full_pairs = transport_len / 2;
    bpf_loop(full_pairs, csum_safe_callback, &sctx, 0);

    sum += sctx.sum;

    // Handle odd byte separately (not included in loop to avoid 2-byte read failure)
    if (transport_len & 1) {
        __u8 odd_byte;
        if (bpf_xdp_load_bytes(ctx, transport_offset + transport_len - 1, &odd_byte, 1) < 0) {
            DEBUG_PRINT("calc_transport_csum_ipv4: failed to load odd byte at offset %u\n", transport_offset + transport_len - 1);
            // Continue with partial checksum - odd byte contributes 0
        } else {
            sum += odd_byte << 8;
        }
    }

    __u16 result = csum_fold(sum);

    // UDP checksum of 0 means no checksum, use 0xFFFF instead
    if (result == 0 && protocol == IPPROTO_UDP)
        result = 0xFFFF;

    return bpf_htons(result);
}

// Calculate transport layer checksum over IPv6
// If final_dst is non-NULL, use it for pseudo-header instead of IPv6 header's daddr
// (required for SRv6 per RFC 8200 - use final destination from SRH)
static __always_inline __u16 calc_transport_csum_ipv6(struct xdp_md *ctx, __u16 ip6_offset, __u16 transport_offset,
                                                      __u16 transport_len, __u8 protocol, __u8 *final_dst)
{
    struct ipv6hdr ip6h;

    // Load IPv6 header using helper
    if (bpf_xdp_load_bytes(ctx, ip6_offset, &ip6h, sizeof(ip6h)) < 0) {
        DEBUG_PRINT("calc_transport_csum_ipv6: failed to load IPv6 header at offset %u\n", ip6_offset);
        return 0;
    }

    __u32 sum = 0;

    // Pseudo-header: source and destination IPv6 addresses
    // Per RFC 8200, if Routing header exists, use final destination from it
    __u16 *src = (__u16 *)&ip6h.saddr;
    __u16 *dst = final_dst ? (__u16 *)final_dst : (__u16 *)&ip6h.daddr;

    for (int i = 0; i < 8; i++) {
        sum += bpf_ntohs(src[i]);
        sum += bpf_ntohs(dst[i]);
    }

    // Upper-layer packet length and next header
    sum += transport_len;
    sum += protocol;

    // Clear checksum field in packet using helper
    __be16 zero_csum = 0;
    __u16 csum_field_offset;
    switch (protocol) {
    case IPPROTO_UDP:
        csum_field_offset = UDP_CSUM_OFFSET;
        break;
    case IPPROTO_TCP:
        csum_field_offset = TCP_CSUM_OFFSET;
        break;
    case IPPROTO_ICMPV6:
        csum_field_offset = ICMPV6_CSUM_OFFSET;
        break;
    default:
        DEBUG_PRINT("calc_transport_csum_ipv6: unsupported protocol %u\n", protocol);
        return 0;
    }

    if (bpf_xdp_store_bytes(ctx, transport_offset + csum_field_offset, &zero_csum, 2) < 0) {
        DEBUG_PRINT("calc_transport_csum_ipv6: failed to clear checksum at offset %u\n", transport_offset + csum_field_offset);
        return 0;
    }

    // Sum transport header + payload using bpf_loop with safe callback
    // Only iterate over complete 2-byte pairs to avoid read failures at odd lengths
    struct csum_safe_ctx sctx = {
        .ctx = ctx,
        .offset = transport_offset,
        .sum = 0,
    };

    __u32 full_pairs = transport_len / 2;
    bpf_loop(full_pairs, csum_safe_callback, &sctx, 0);

    sum += sctx.sum;

    // Handle odd byte separately (not included in loop to avoid 2-byte read failure)
    if (transport_len & 1) {
        __u8 odd_byte;
        if (bpf_xdp_load_bytes(ctx, transport_offset + transport_len - 1, &odd_byte, 1) < 0) {
            DEBUG_PRINT("calc_transport_csum_ipv6: failed to load odd byte at offset %u\n", transport_offset + transport_len - 1);
            // Continue with partial checksum - odd byte contributes 0
        } else {
            sum += odd_byte << 8;
        }
    }

    return bpf_htons(csum_fold(sum));
}

#endif // XDP_CHECKSUM_H
