#include "xdp_prog.h"
#include "xdpcap.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
SEC("xdp")
int xdp_tx(struct xdp_md *ctx)
{
	int key = 0;
	struct datarec *rec = bpf_map_lookup_elem(&stats_map, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->rx_packets++;
	rec->rx_bytes += ctx->data_end - ctx->data;
	return XDP_TX;
};