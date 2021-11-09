#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>

struct resource_metrics {
  METRICS
};

// Each Collector needs a handle to read perf counters
BPF_PERF_ARRAY(cpu_cycles, MAX_CPUS);
BPF_PERF_ARRAY(instructions, MAX_CPUS);
BPF_PERF_ARRAY(cache_references, MAX_CPUS);
BPF_PERF_ARRAY(cache_misses, MAX_CPUS);
BPF_PERF_ARRAY(ref_cpu_cycles, MAX_CPUS);

// Each OU gets its own ou_id,plan_node_id->metrics for incomplete data.
BPF_HASH(incomplete_metrics, u64, struct resource_metrics);

// We expect `plan_node_id` to be unique within the call stack, even if OUs are recursive.
static u64 incomplete_metrics_key(const u32 ou, const s32 plan_node_id) { return ((u64)ou) << 32 | plan_node_id; }
