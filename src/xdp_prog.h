#ifndef XDP_UTILS_H
#define XDP_UTILS_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

#ifdef XDPERF_DEBUG
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) (void)0
#endif

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

#define MAX_PACKET_ENTRY 2048
#define MAX_TEMPLATE_SIZE 2048
struct pkt_template {
    __u32 len;                    // actual length of data
    __u8 data[MAX_TEMPLATE_SIZE]; // raw frame
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_PACKET_ENTRY);
    __type(key, __u32); // per-cpu id
    __type(value, struct pkt_template);
} tx_override_map SEC(".maps");

// random or sequential per-cpu state
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} seq_state_map SEC(".maps");

// number of valid packet entries per CPU in tx_override_map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pkt_count_map SEC(".maps");

// https://github.com/cloudflare/xdpcap
// struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();
struct xdpcap_hook {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 5);
} xdpcap_hook SEC(".maps");

#endif // XDP_UTILS_H
