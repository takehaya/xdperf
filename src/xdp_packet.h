#ifndef XDP_PACKET_H
#define XDP_PACKET_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// Maximum template size (same as existing)
#define MAX_TEMPLATE_SIZE 2048

// Maximum number of diffs per packet
#define MAX_DIFFS_PER_PACKET 8

// Maximum number of diff entries (per CPU)
#define MAX_DIFF_ENTRIES 131072

// Maximum number of checksum metadata entries per base packet
// Must match maxChecksumEntriesPerBase in pkg/xdperf/bpf.go
#define MAX_CHECKSUM_ENTRIES 4

// Maximum number of base packets (variants)
// Must match maxBasePackets in pkg/xdperf/generator.go
#define MAX_BASE_PACKETS 16

// Checksum types
#define CSUM_TYPE_IPV4_HEADER 0
#define CSUM_TYPE_UDP_IPV4 1
#define CSUM_TYPE_TCP_IPV4 2
#define CSUM_TYPE_UDP_IPV6 3
#define CSUM_TYPE_TCP_IPV6 4
#define CSUM_TYPE_ICMPV6 5

// Base packet structure (stored once per variant)
struct base_packet {
    __u16 len;                    // Base packet length
    __u8 checksum_count;          // Number of checksums to recalculate
    __u8 _pad;                    // Padding for alignment
    __u8 data[MAX_TEMPLATE_SIZE]; // Base packet data
};

// Single diff value
struct diff_value {
    __u16 offset; // Byte offset in packet
    __u8 size;    // 1, 2, or 4 bytes
    __u8 _pad;
    __u32 old_value; // Original value from base packet (big-endian)
    __u32 new_value; // New value to write (big-endian)
};

// Diff entry for one packet (contains all diffs for that packet)
struct diff_entry {
    __u8 base_idx;    // Index into base_packet_map (which base to use)
    __u8 diff_count;  // Actual number of diffs in this entry
    __u16 pkt_len;    // Packet length (for variable length)
    __u8 len_changed; // 1 if pkt_len differs from base, 0 otherwise (affects checksum handling)
    __u8 _pad[3];     // Padding for alignment
    struct diff_value diffs[MAX_DIFFS_PER_PACKET];
};

// Checksum metadata (how to recalculate checksums)
struct checksum_meta {
    __u8 csum_type; // CSUM_TYPE_* constant
    __u8 _pad;
    __u16 csum_offset;      // Offset of checksum field in packet
    __u16 header_start;     // Start of header to checksum
    __u16 header_len;       // Length of header (0 = compute from IP/transport length)
    __u16 ip_header_offset; // Offset of IP header (for pseudo-header)
    __u16 _pad2;
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

// Checksum metadata map (shared, read-only)
// Key: base_idx * MAX_CHECKSUM_ENTRIES + checksum_idx
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
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

#endif // XDP_PACKET_H
