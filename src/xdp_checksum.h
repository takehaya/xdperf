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

// Fold 32-bit checksum to 16-bit
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

// Calculate full IPv4 header checksum
static __always_inline __u16 calc_ipv4_header_csum(struct xdp_md *ctx, __u16 ip_offset)
{
    struct iphdr iph;

    // Load IP header to stack using helper - handles bounds internally
    if (bpf_xdp_load_bytes(ctx, ip_offset, &iph, sizeof(iph)) < 0) {
        DEBUG_PRINT("calc_ipv4_header_csum: failed to load IP header at offset %u\n", ip_offset);
        return 0;
    }

    __u16 *ptr = (__u16 *)&iph;
    __u32 sum = 0;

// IPv4 header is 20 bytes = 10 x 16-bit words
// Skip checksum field (index 5) in calculation
#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (i != 5) // Skip checksum field
            sum += bpf_ntohs(ptr[i]);
    }

    return bpf_htons(csum_fold(sum));
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
    __u16 csum_field_offset = (protocol == IPPROTO_UDP) ? 6 : 16;
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
static __always_inline __u16 calc_transport_csum_ipv6(struct xdp_md *ctx, __u16 ip6_offset, __u16 transport_offset,
                                                      __u16 transport_len, __u8 protocol)
{
    struct ipv6hdr ip6h;

    // Load IPv6 header using helper
    if (bpf_xdp_load_bytes(ctx, ip6_offset, &ip6h, sizeof(ip6h)) < 0) {
        DEBUG_PRINT("calc_transport_csum_ipv6: failed to load IPv6 header at offset %u\n", ip6_offset);
        return 0;
    }

    __u32 sum = 0;

    // Pseudo-header: source and destination IPv6 addresses
    __u16 *src = (__u16 *)&ip6h.saddr;
    __u16 *dst = (__u16 *)&ip6h.daddr;

#pragma unroll
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
        csum_field_offset = 6;
        break;
    case IPPROTO_TCP:
        csum_field_offset = 16;
        break;
    case IPPROTO_ICMPV6:
        csum_field_offset = 2;
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
