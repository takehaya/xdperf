/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal kernel-type and kfunc declarations for the xdperf sched_ext
 * scheduler (scx_prog.c).
 *
 * xdperf's BPF build intentionally carries no vmlinux.h; the data-plane
 * programs use UAPI headers only. sched_ext needs a handful of
 * kernel-internal types, so they are hand-declared here with
 * preserve_access_index: CO-RE relocates every field access against the
 * running kernel's BTF, and partial struct definitions (only the fields we
 * read, in any order) are sufficient.
 *
 * kfuncs use their kernel >= 6.13 names (scx_bpf_dispatch was renamed to
 * scx_bpf_dsq_insert in 6.13); the Go loader refuses older kernels.
 */
#ifndef SCX_KERNEL_DEFS_H
#define SCX_KERNEL_DEFS_H

#include <linux/types.h>
#include <stdbool.h>

typedef __s32 s32;
typedef __s64 s64;
typedef __u32 u32;
typedef __u64 u64;

/*
 * Used through pointers only, but kfunc argument matching needs a struct
 * definition (a forward declaration is BTF kind Fwd and gets rejected). The
 * real bitmap length depends on the kernel's NR_CPUS; irrelevant here since
 * the struct is never dereferenced or copied.
 */
struct cpumask {
    unsigned long bits[1];
} __attribute__((preserve_access_index));

struct task_struct {
    int pid;
    int tgid;
    int nr_cpus_allowed;
    const struct cpumask *cpus_ptr;
    char comm[16];
} __attribute__((preserve_access_index));

/*
 * CO-RE field matching pairs enums with enums, so kind must be declared as
 * the kernel enum (name match), not as int. Values mirror kernel/sched/ext.h;
 * >= SCX_EXIT_ERROR means an abnormal exit (ERROR_STALL = watchdog eject).
 */
enum scx_exit_kind {
    SCX_EXIT_NONE = 0,
    SCX_EXIT_DONE = 1,
    SCX_EXIT_UNREG = 64,
    SCX_EXIT_UNREG_BPF = 65,
    SCX_EXIT_UNREG_KERN = 66,
    SCX_EXIT_SYSRQ = 67,
    SCX_EXIT_ERROR = 1024,
    SCX_EXIT_ERROR_BPF = 1025,
    SCX_EXIT_ERROR_STALL = 1026,
};

struct scx_exit_info {
    enum scx_exit_kind kind;
    s64 exit_code;
    const char *reason;
    char *msg;
} __attribute__((preserve_access_index));

/*
 * The parts of struct sched_ext_ops this scheduler implements. The loader
 * matches members to the kernel struct by NAME and translates offsets, so a
 * partial declaration in any order is fine.
 */
struct sched_ext_ops {
    s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
    void (*enqueue)(struct task_struct *p, u64 enq_flags);
    void (*dispatch)(s32 cpu, struct task_struct *prev);
    s32 (*init)(void);
    void (*exit)(struct scx_exit_info *ei);
    char name[128];
};

/*
 * Stable sched_ext ABI constants, mirroring kernel/sched/ext.h. The DSQ id
 * encoding, enqueue flags and slice values are part of the documented BPF
 * scheduler interface (Documentation/scheduler/sched-ext.rst).
 */
#define SCX_DSQ_FLAG_BUILTIN (1ULL << 63)
#define SCX_DSQ_FLAG_LOCAL_ON (1ULL << 62)
#define SCX_DSQ_LOCAL (SCX_DSQ_FLAG_BUILTIN | 2)
#define SCX_DSQ_LOCAL_ON (SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON)
#define SCX_ENQ_WAKEUP 1ULL
#define SCX_ENQ_PREEMPT (1ULL << 32)
#define SCX_SLICE_DFL (20 * 1000000ULL) /* 20ms */
#define SCX_SLICE_INF (~0ULL)           /* no tick-driven expiry */

/* sched_ext kfuncs (6.13+ names) */
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
extern u32 scx_bpf_nr_cpu_ids(void) __ksym;
extern s32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;

/* cpumask kfunc: works on trusted kernel cpumasks such as p->cpus_ptr */
extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;

/* struct_ops callback wrappers (libbpf's BPF_PROG unpacks the ctx array) */
#define BPF_STRUCT_OPS(name, args...)                                                                                              \
    SEC("struct_ops/" #name)                                                                                                       \
    BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)                                                                                    \
    SEC("struct_ops.s/" #name)                                                                                                     \
    BPF_PROG(name, ##args)

#endif /* SCX_KERNEL_DEFS_H */
