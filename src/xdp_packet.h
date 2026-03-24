#ifndef XDP_PACKET_H
#define XDP_PACKET_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// Maximum packet size
#define MAX_PACKET_SIZE 2048

// Maximum number of diffs per packet
#define MAX_DIFFS_PER_PACKET 6

// Maximum number of diff entries (per CPU)
#define MAX_DIFF_ENTRIES 131072

// Maximum number of checksum metadata entries per base packet
#define MAX_CHECKSUM_ENTRIES 4

// Maximum number of base packets (variants)
#define MAX_BASE_PACKETS 16

// Expose constants to Go via spec.Variables
volatile __u32 max_packet_size = MAX_PACKET_SIZE;
volatile __u32 max_diffs_per_packet = MAX_DIFFS_PER_PACKET;
volatile __u32 max_base_packets = MAX_BASE_PACKETS;
volatile __u32 max_checksum_entries = MAX_CHECKSUM_ENTRIES;

// Base packet structure (stored once per variant)
struct base_packet {
    __u16 len;                  // Base packet length
    __u8 checksum_count;        // Number of checksums to recalculate
    __u8 _pad;                  // Padding for alignment
    __u8 data[MAX_PACKET_SIZE]; // Base packet data
};

// Single diff value
struct diff_value {
    __u8 old_value[8]; // Original value from base packet (big-endian)
    __u8 new_value[8]; // New value to write (big-endian)
    __u16 offset;      // Byte offset in packet
    __u8 size;         // 1, 2, 4, 6, or 8 bytes
};

// Diff entry for one packet (contains all diffs for that packet)
struct diff_entry {
    struct diff_value diffs[MAX_DIFFS_PER_PACKET];
    __u16 pkt_len;    // Packet length (for variable length)
    __u8 base_idx;    // Index into base_packet_map (which base to use)
    __u8 diff_count;  // Actual number of diffs in this entry
    __u8 len_changed; // 1 if pkt_len differs from base, 0 otherwise (affects checksum handling)
};

// Checksum metadata (how to recalculate checksums)
// The checksum type is auto-detected from packet content at ip_header_offset.
// For IPv4 header checksum, set csum_offset == header_start (IP header start).
struct checksum_meta {
    __u16 csum_offset;      // Offset of checksum field in packet
    __u16 header_start;     // Start of header to checksum
    __u16 header_len;       // Length of header (0 = compute from IP/transport length)
    __u16 ip_header_offset; // Offset of IP header (for pseudo-header)
};

// Per-CPU packet state
struct pkt_state {
    __u32 count; // Number of valid diff entries
    __u32 idx;   // Current index (round-robin)
};

// Base packet map (multiple base packets for different variants)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BASE_PACKETS);
    __type(key, __u32);
    __type(value, struct base_packet);
} base_packet_map SEC(".maps");

// Diff entries map (pre-computed diffs)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_DIFF_ENTRIES);
    __type(key, __u32);
    __type(value, struct diff_entry);
} diff_map SEC(".maps");

// Checksum metadata map (per-CPU, read-only)
// Key: base_idx * MAX_CHECKSUM_ENTRIES + checksum_idx
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BASE_PACKETS *MAX_CHECKSUM_ENTRIES);
    __type(key, __u32);
    __type(value, struct checksum_meta);
} checksum_meta_map SEC(".maps");

// Per-CPU packet state map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_state);
} pkt_state_map SEC(".maps");

// TX stats map (uses struct datarec from xdp_prog.h)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1);
} tx_stats_map SEC(".maps");

// Tail call context - passed between xdp_tx and xdp_tx_checksum
// This allows splitting the program to avoid verifier instruction limit
struct tail_call_ctx {
    __u32 base_idx;      // Index into base_packet_map
    __u32 local_idx;     // Current diff index for round-robin update
    __u16 target_len;    // Target packet length
    __u8 diff_count;     // Number of diffs applied
    __u8 checksum_count; // Number of checksums to process
    __u8 len_changed;    // Whether packet length changed from base
    __u8 diff_errors;    // Count of diff application errors
    __u8 _pad[2];        // Padding for alignment
};

// Tail call context map (per-CPU) - passes data between tail-called programs
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tail_call_ctx);
} tail_call_ctx_map SEC(".maps");

// Program array for tail calls
// Index 0: xdp_tx_checksum (len_changed path)
// Index 1: xdp_tx_csum_diff (incremental checksum path)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} xdp_progs SEC(".maps");

#define XDP_PROG_CHECKSUM 0
#define XDP_PROG_CSUM_DIFF 1

#endif // XDP_PACKET_H
