#ifndef XDPCAP_HOOK_H
#define XDPCAP_HOOK_H

#include <linux/bpf.h>

// Runtime configurable: set to 1 to enable xdpcap (default: 0 for max performance)
// Can be controlled via --enable-xdpcap flag
const volatile __u32 enable_xdpcap = 0;

// Performance mode: bypass xdpcap for maximum throughput by default
// When enable_xdpcap is set, xdpcap_exit is called for packet capture support
#define RETURN_ACTION(ctx, hook, action)                                                                                           \
    do {                                                                                                                           \
        if (enable_xdpcap)                                                                                                         \
            return xdpcap_exit(ctx, hook, action);                                                                                 \
        return (action);                                                                                                           \
    } while (0)

/**
 * Create a bpf map suitable for use as an xdpcap hook point.
 *
 * For example:
 *   struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();
 */
#define XDPCAP_HOOK()                                                                                                              \
    {                                                                                                                              \
        .type = BPF_MAP_TYPE_PROG_ARRAY, .key_size = sizeof(int), .value_size = sizeof(int), .max_entries = 5,                     \
    }

/**
 * Return action, exposing the action and input packet to xdpcap hook.
 *
 *   return xdpcap_exit(ctx, &hook, XDP_PASS)
 *
 * is equivalent to:
 *
 *   return XDP_PASS;
 */
__attribute__((__always_inline__)) static inline enum xdp_action xdpcap_exit(struct xdp_md *ctx, void *hook_map,
                                                                             enum xdp_action action)
{
    // tail_call
    // Some headers define tail_call (Cilium), others bpf_tail_call (kernel self
    // tests). Use the helper ID directly
    ((int (*)(struct xdp_md *, void *, int))12)(ctx, hook_map, action);
    return action;
}

#endif /* XDPCAP_HOOK_H */
