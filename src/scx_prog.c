// SPDX-License-Identifier: GPL-2.0
/*
 * scx_prog.c - xdperf's sched_ext CPU-isolation scheduler (--scx).
 *
 * A full-switch scheduler (all SCHED_NORMAL tasks run under it while
 * attached) that dedicates the TX worker CPUs to xdperf. Three task classes
 * (design: docs/ja/scx_design.md):
 *
 *   WORKER  registered xdperf TX threads -> their own CPU's local DSQ with an
 *           effectively infinite slice; wakeups preempt whatever runs there.
 *   PINNED  tasks that cannot run anywhere but worker CPUs (percpu kthreads)
 *           -> their CPU with a tiny slice and preemption. Nothing starves,
 *           so the sched_ext stall watchdog never ejects the scheduler.
 *   OTHER   everything else -> one shared FIFO, consumed exclusively by
 *           non-worker CPUs.
 *
 * The isolation rests on two invariants: select_cpu never returns a worker
 * CPU for OTHER tasks, and dispatch on a worker CPU never pulls from the
 * shared queue. Detach (link close) restores the kernel's default scheduler.
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "scx_kernel_defs.h"

char _license[] SEC("license") = "GPL";

/* Custom DSQ holding all OTHER tasks. */
#define SHARED_DSQ 0

#define MAX_CPUS 1024
#define MASK_WORDS (MAX_CPUS / 64)

/* Bounded interruption for tasks confined to a worker CPU. */
#define SLICE_PINNED_NS (20 * 1000ULL) /* 20us */

/* Set by the loader before load. tgid guards against TID reuse: a recycled
 * thread id from another process must not inherit worker treatment. */
const volatile u32 xdperf_tgid;
const volatile u64 worker_cpu_mask[MASK_WORDS];

/* tid -> assigned CPU, populated by the loader before attach. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u32);
} worker_tids SEC(".maps");

/* Exit record read back by the loader (watchdog eject vs clean detach). */
struct scx_exit_record {
    u32 set;
    s32 kind;
    s64 exit_code;
    char reason[64];
    char msg[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scx_exit_record);
} exit_info SEC(".maps");

_Static_assert((MASK_WORDS & (MASK_WORDS - 1)) == 0, "MASK_WORDS must be a power of two for the index masking below");

static __always_inline bool is_worker_cpu(s32 cpu)
{
    u32 word, bit;

    if (cpu < 0 || cpu >= MAX_CPUS)
        return false;
    /* Bound the word index by construction (mask, not branch): the verifier
     * then sees an in-range offset no matter how the compiler re-associates
     * the arithmetic. */
    word = ((u32)cpu >> 6) & (MASK_WORDS - 1);
    bit = (u32)cpu & 63;
    return worker_cpu_mask[word] & (1ULL << bit);
}

static __always_inline bool worker_cpu_of(struct task_struct *p, s32 *cpu)
{
    u32 tid, *val;

    if ((u32)p->tgid != xdperf_tgid)
        return false;
    tid = p->pid; /* kernel-side pid of a thread == its TID */
    val = bpf_map_lookup_elem(&worker_tids, &tid);
    if (!val)
        return false;
    *cpu = (s32)*val;
    return true;
}

/* A task is confined when no CPU outside the worker set may run it. The scan
 * exits at the first escape CPU, so for regular tasks this is O(1). */
static bool confined_to_worker_cpus(struct task_struct *p)
{
    u32 nr = scx_bpf_nr_cpu_ids();
    u32 cpu;

    for (cpu = 0; cpu < MAX_CPUS; cpu++) {
        if (cpu >= nr)
            break;
        if (is_worker_cpu((s32)cpu))
            continue;
        if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
            return false;
    }
    return true;
}

/* Only tasks with nr_cpus_allowed > 1 reach select_cpu (the core skips it
 * for pinned tasks), so this places OTHER tasks: keep them off worker CPUs,
 * preferring the previous CPU for cache locality. */
s32 BPF_STRUCT_OPS(xdperf_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    u32 nr = scx_bpf_nr_cpu_ids();
    s32 cpu;
    u32 i;

    if (worker_cpu_of(p, &cpu))
        return cpu;

    if (!is_worker_cpu(prev_cpu) && bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr))
        return prev_cpu;

    for (i = 0; i < MAX_CPUS; i++) {
        if (i >= nr)
            break;
        if (is_worker_cpu((s32)i))
            continue;
        if (bpf_cpumask_test_cpu(i, p->cpus_ptr))
            return (s32)i;
    }

    /* No escape CPU: fall through, enqueue confines it with a tiny slice. */
    return prev_cpu;
}

void BPF_STRUCT_OPS(xdperf_enqueue, struct task_struct *p, u64 enq_flags)
{
    s32 cpu;

    if (worker_cpu_of(p, &cpu)) {
        /* Preempt only on wakeup: a preempted worker re-enqueues here
         * too, and preempting back would live-lock against PINNED. */
        u64 preempt = (enq_flags & SCX_ENQ_WAKEUP) ? SCX_ENQ_PREEMPT : 0;

        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u32)cpu, SCX_SLICE_INF, enq_flags | preempt);
        return;
    }

    if (confined_to_worker_cpus(p)) {
        cpu = scx_bpf_task_cpu(p);
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u32)cpu, SLICE_PINNED_NS, enq_flags | SCX_ENQ_PREEMPT);
        return;
    }

    scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(xdperf_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Worker CPUs never pull from the shared queue: an idle worker CPU
     * stays free so its worker resumes instantly. */
    if (is_worker_cpu(cpu))
        return;
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(xdperf_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(xdperf_exit, struct scx_exit_info *ei)
{
    u32 key = 0;
    struct scx_exit_record *rec = bpf_map_lookup_elem(&exit_info, &key);

    if (!rec)
        return;
    rec->kind = ei->kind;
    rec->exit_code = ei->exit_code;
    bpf_probe_read_kernel_str(rec->reason, sizeof(rec->reason), ei->reason);
    bpf_probe_read_kernel_str(rec->msg, sizeof(rec->msg), ei->msg);
    rec->set = 1;
}

SEC(".struct_ops.link")
struct sched_ext_ops xdperf_ops = {
    .select_cpu = (void *)xdperf_select_cpu,
    .enqueue = (void *)xdperf_enqueue,
    .dispatch = (void *)xdperf_dispatch,
    .init = (void *)xdperf_init,
    .exit = (void *)xdperf_exit,
    .name = "xdperf",
};
