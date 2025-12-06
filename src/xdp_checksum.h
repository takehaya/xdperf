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

// Fold 32-bit checksum to 16-bit
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

// Update checksum incrementally using bpf_csum_diff
// This is used when packet length doesn't change
static __always_inline int update_csum_incremental(void *data, void *data_end, __u16 csum_offset, __u32 old_val, __u32 new_val,
                                                   __u8 size)
{
    if (data + csum_offset + 2 > data_end)
        return -1;

    __be16 *csum_ptr = data + csum_offset;
    __u32 old_csum = bpf_ntohs(*csum_ptr);

    // Calculate diff using bpf_csum_diff
    __be32 from_buf = bpf_htonl(old_val);
    __be32 to_buf = bpf_htonl(new_val);

    __s64 diff = bpf_csum_diff(&from_buf, size, &to_buf, size, 0);
    if (diff < 0)
        return -1;

    // Apply diff to existing checksum
    __u32 new_csum = ~old_csum & 0xFFFF;
    new_csum += (__u32)diff;

    // Fold and store
    *csum_ptr = bpf_htons(csum_fold(new_csum));

    return 0;
}

// Context for bpf_loop checksum calculation
struct csum_loop_ctx {
    void *data;
    void *data_end;
    __u32 offset;
    __u32 len;
    __u32 sum;
};

// Callback for bpf_loop checksum calculation
static long csum_loop_callback(__u32 idx, void *ctx)
{
    struct csum_loop_ctx *c = ctx;
    __u32 byte_offset = c->offset + idx * 2;

    if (c->data + byte_offset + 2 > c->data_end)
        return 1; // Stop iteration

    __u16 *ptr = c->data + byte_offset;
    c->sum += bpf_ntohs(*ptr);

    return 0;
}

// Calculate full IPv4 header checksum
static __always_inline __u16 calc_ipv4_header_csum(void *data, void *data_end, __u16 ip_offset)
{
    if (data + ip_offset + sizeof(struct iphdr) > data_end)
        return 0;

    struct iphdr *iph = data + ip_offset;
    __u16 *ptr = (void *)iph;
    __u32 sum = 0;

    // IPv4 header is 20 bytes = 10 x 16-bit words
    // Clear checksum field before calculation
    iph->check = 0;

#pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += bpf_ntohs(ptr[i]);
    }

    return bpf_htons(csum_fold(sum));
}

// Safe version using bpf_xdp_load_bytes to avoid verifier issues with variable offsets
static __always_inline __u16 calc_ipv4_header_csum_safe(struct xdp_md *ctx, __u16 ip_offset)
{
    struct iphdr iph;

    // Load IP header to stack using helper - handles bounds internally
    if (bpf_xdp_load_bytes(ctx, ip_offset, &iph, sizeof(iph)) < 0)
        return 0;

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

// Safe version of transport checksum using bpf_xdp_load_bytes
static __always_inline __u16 calc_transport_csum_ipv4_safe(struct xdp_md *ctx, __u16 ip_offset, __u16 transport_offset,
                                                           __u16 transport_len, __u8 protocol)
{
    struct iphdr iph;

    // Load IP header using helper
    if (bpf_xdp_load_bytes(ctx, ip_offset, &iph, sizeof(iph)) < 0)
        return 0;

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
    if (bpf_xdp_store_bytes(ctx, transport_offset + csum_field_offset, &zero_csum, 2) < 0)
        return 0;

    // Sum transport header + payload using bpf_loop with safe callback
    struct csum_safe_ctx sctx = {
        .ctx = ctx,
        .offset = transport_offset,
        .sum = 0,
    };

    __u32 iterations = (transport_len + 1) / 2;
    bpf_loop(iterations, csum_safe_callback, &sctx, 0);

    sum += sctx.sum;

    // Handle odd byte
    if (transport_len & 1) {
        __u8 odd_byte;
        if (bpf_xdp_load_bytes(ctx, transport_offset + transport_len - 1, &odd_byte, 1) == 0)
            sum += odd_byte << 8;
    }

    __u16 result = csum_fold(sum);

    // UDP checksum of 0 means no checksum, use 0xFFFF instead
    if (result == 0 && protocol == IPPROTO_UDP)
        result = 0xFFFF;

    return bpf_htons(result);
}

// Calculate transport layer checksum (UDP/TCP) over IPv4
// Uses bpf_loop for variable length payloads
static __always_inline __u16 calc_transport_csum_ipv4(void *data, void *data_end, __u16 ip_offset, __u16 transport_offset,
                                                      __u16 transport_len, __u8 protocol)
{
    if (data + ip_offset + sizeof(struct iphdr) > data_end)
        return 0;
    if (data + transport_offset + transport_len > data_end)
        return 0;

    struct iphdr *iph = data + ip_offset;
    __u32 sum = 0;

    // Pseudo-header
    __u32 saddr = bpf_ntohl(iph->saddr);
    __u32 daddr = bpf_ntohl(iph->daddr);

    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += protocol;
    sum += transport_len;

    // Clear checksum field
    if (protocol == IPPROTO_UDP) {
        if (data + transport_offset + sizeof(struct udphdr) > data_end)
            return 0;
        struct udphdr *udph = data + transport_offset;
        udph->check = 0;
    } else if (protocol == IPPROTO_TCP) {
        if (data + transport_offset + sizeof(struct tcphdr) > data_end)
            return 0;
        struct tcphdr *tcph = data + transport_offset;
        tcph->check = 0;
    }

    // Sum transport header + payload using bpf_loop
    struct csum_loop_ctx ctx = {
        .data = data,
        .data_end = data_end,
        .offset = transport_offset,
        .len = transport_len,
        .sum = 0,
    };

    __u32 iterations = (transport_len + 1) / 2;
    bpf_loop(iterations, csum_loop_callback, &ctx, 0);

    sum += ctx.sum;

    // Handle odd byte
    if (transport_len & 1) {
        __u8 *odd = data + transport_offset + transport_len - 1;
        if ((void *)(odd + 1) <= data_end)
            sum += (*odd) << 8;
    }

    __u16 result = csum_fold(sum);

    // UDP checksum of 0 means no checksum, use 0xFFFF instead
    if (result == 0 && protocol == IPPROTO_UDP)
        result = 0xFFFF;

    return bpf_htons(result);
}

// Calculate transport layer checksum over IPv6
static __always_inline __u16 calc_transport_csum_ipv6(void *data, void *data_end, __u16 ip6_offset, __u16 transport_offset,
                                                      __u16 transport_len, __u8 protocol)
{
    if (data + ip6_offset + sizeof(struct ipv6hdr) > data_end)
        return 0;
    if (data + transport_offset + transport_len > data_end)
        return 0;

    struct ipv6hdr *ip6h = data + ip6_offset;
    __u32 sum = 0;

    // Pseudo-header: source and destination IPv6 addresses
    __u16 *src = (__u16 *)&ip6h->saddr;
    __u16 *dst = (__u16 *)&ip6h->daddr;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        sum += bpf_ntohs(src[i]);
        sum += bpf_ntohs(dst[i]);
    }

    // Upper-layer packet length and next header
    sum += transport_len;
    sum += protocol;

    // Clear checksum field
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
        return 0;
    }

    if (data + transport_offset + csum_field_offset + 2 > data_end)
        return 0;

    __u16 *csum_ptr = data + transport_offset + csum_field_offset;
    *csum_ptr = 0;

    // Sum transport data using bpf_loop
    struct csum_loop_ctx ctx = {
        .data = data,
        .data_end = data_end,
        .offset = transport_offset,
        .len = transport_len,
        .sum = 0,
    };

    __u32 iterations = (transport_len + 1) / 2;
    bpf_loop(iterations, csum_loop_callback, &ctx, 0);

    sum += ctx.sum;

    // Handle odd byte
    if (transport_len & 1) {
        __u8 *odd = data + transport_offset + transport_len - 1;
        if ((void *)(odd + 1) <= data_end)
            sum += (*odd) << 8;
    }

    return bpf_htons(csum_fold(sum));
}

#endif // XDP_CHECKSUM_H
