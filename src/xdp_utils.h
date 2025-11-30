#ifndef XDP_UTIL_H
#define XDP_UTIL_H
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

volatile int server_mode = 0;

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static __always_inline void swap_mac(struct ethhdr *eth)
{
     if (server_mode == 0) {
        return;
    }
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

static __always_inline void swap_ipv4(struct iphdr *iph)
{
    if (server_mode == 0) {
        return;
    }
    __be32 tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
}

static __always_inline void swap_ipv6(struct ipv6hdr *ip6h)
{
     if (server_mode == 0) {
        return;
    }
    struct in6_addr tmp = ip6h->saddr;
    ip6h->saddr = ip6h->daddr;
    ip6h->daddr = tmp;
}

#endif // XDP_UTIL_H
