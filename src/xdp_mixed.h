#ifndef XDP_MIXED_H
#define XDP_MIXED_H

// Separate tail-call graph keeps TCP and checksum verifier state independent.
struct mixed_cfg {
    __u32 total_weight;
    __u32 packet_weight;
    __u32 groups;
    __u32 workers;
    __u32 receive;
};
struct mixed_group {
    __u32 upper;
    __u32 first;
    __u32 count;
    __u32 cursor;
};
struct mixed_state {
    __u64 packet_opportunities;
    __u64 tcp_opportunities;
    __u64 drain_opportunities;
    __u64 errors;
    __u32 selected_flow;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mixed_cfg);
} mixed_cfg_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct mixed_group);
} mixed_group_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mixed_state);
} mixed_state_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} mixed_progs SEC(".maps");
#endif
