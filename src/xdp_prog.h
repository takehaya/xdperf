#ifndef XDP_PROG_H
#define XDP_PROG_H
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
    __u64 packets;
    __u64 bytes;
    __u64 diff_errors;     // Failed diff applications
    __u64 checksum_errors; // Failed checksum calculations
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1);
} rx_stats_map SEC(".maps");

#endif // XDP_PROG_H
