#include "xdp_prog.h"
#include "xdpcap.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <stdbool.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_tx(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 zero = 0;

  __u32 *pidx = bpf_map_lookup_elem(&seq_state_map, &zero);
  __u32 idx = pidx ? *pidx : 0;
  if (idx >= MAX_PACKET_ENTRY)
    idx = 0;

  struct pkt_template *pt = bpf_map_lookup_elem(&tx_override_map, &idx);
  if (!pt)
    return XDP_ABORTED;

  __u32 tlen = pt->len;
  if (tlen > MAX_TEMPLATE_SIZE)
    tlen = MAX_TEMPLATE_SIZE;

  __u32 cur_len = data_end - data;
  if (cur_len != tlen) {
    int delta = (int)tlen - (int)cur_len;
    if (bpf_xdp_adjust_tail(ctx, delta) < 0)
      return XDP_ABORTED;
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data + tlen > data_end)
      return XDP_ABORTED;
  }

  // override payload
  if (data + tlen > data_end)
    return XDP_ABORTED;

  for (int i = 0; i < MAX_TEMPLATE_SIZE; i++) {
    if (i >= (int)tlen)
      break;

    void *dp = data + i;
    if (dp + 1 > data_end)
      return XDP_ABORTED;

    *(__u8 *)dp = pt->data[i];
  }

  // next index
  if (pidx) {
    __u32 next = idx + 1;
    if (next >= MAX_PACKET_ENTRY)
      next = 0;
    *pidx = next;
  }

  // sended packet stats
  struct datarec *rec = bpf_map_lookup_elem(&stats_map, &zero);
  if (!rec)
    return XDP_ABORTED;
  rec->rx_packets++;
  rec->rx_bytes += ctx->data_end - ctx->data;
  return XDP_TX;
};
