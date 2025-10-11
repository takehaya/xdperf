#ifndef XDP_UTILS_H
#define XDP_UTILS_H
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, 1);
} stats_map SEC(".maps");

#endif // XDP_UTILS_H