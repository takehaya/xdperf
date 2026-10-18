/* SPDX-License-Identifier: MIT */
/*
 * VXLAN (RFC 7348) layout shared by the xdperf C plugin (built for wasm32)
 * and BPF programs that parse the same traffic (built for bpf). It uses only
 * compiler builtin types so that it compiles for both targets without libc
 * or kernel headers.
 */
#pragma once

typedef __UINT8_TYPE__ vx_u8;
typedef __UINT16_TYPE__ vx_u16;
typedef __UINT32_TYPE__ vx_u32;

#define VXLAN_UDP_PORT 4789
#define VXLAN_FLAG_VNI 0x08

/* Outer Ethernet + IPv4 (no options) + UDP + VXLAN, then the inner frame. */
#define VX_ETH_LEN 14
#define VX_IP4_LEN 20
#define VX_UDP_LEN 8
#define VX_HDR_LEN 8
#define VX_OUTER_LEN (VX_ETH_LEN + VX_IP4_LEN + VX_UDP_LEN + VX_HDR_LEN)
/* Offsets inside the inner frame (Ethernet + IPv4 + UDP). */
#define VX_INNER_IP_OFF VX_ETH_LEN
#define VX_INNER_L4_OFF (VX_ETH_LEN + VX_IP4_LEN)

struct vxlan_hdr {
    vx_u8 flags;
    vx_u8 rsvd0[3];
    vx_u8 vni[3];
    vx_u8 rsvd1;
};

/* The inner 5-tuple a per-flow plugin keys on (network byte order). */
struct vx_inner_key {
    vx_u32 saddr;
    vx_u32 daddr;
    vx_u16 sport;
    vx_u16 dport;
    vx_u32 vni;
};

static inline vx_u32 vxlan_vni(const struct vxlan_hdr *h)
{
    return ((vx_u32)h->vni[0] << 16) | ((vx_u32)h->vni[1] << 8) | h->vni[2];
}

static inline void vxlan_set_vni(struct vxlan_hdr *h, vx_u32 vni)
{
    h->flags = VXLAN_FLAG_VNI;
    h->rsvd0[0] = h->rsvd0[1] = h->rsvd0[2] = 0;
    h->vni[0] = (vx_u8)(vni >> 16);
    h->vni[1] = (vx_u8)(vni >> 8);
    h->vni[2] = (vx_u8)vni;
    h->rsvd1 = 0;
}

/* Big-endian loads from byte buffers that may be unaligned (packet data). */
static inline vx_u16 vx_load16(const vx_u8 *p)
{
    return (vx_u16)(p[0] << 8 | p[1]);
}

static inline vx_u32 vx_load32(const vx_u8 *p)
{
    return (vx_u32)p[0] << 24 | (vx_u32)p[1] << 16 | (vx_u32)p[2] << 8 | p[3];
}
