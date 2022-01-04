#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>

struct resource_metrics {
  SUBST_METRICS;
};

// Each Collector needs a handle to read perf counters
BPF_PERF_ARRAY(cpu_cycles, MAX_CPUS);
BPF_PERF_ARRAY(instructions, MAX_CPUS);
BPF_PERF_ARRAY(cache_references, MAX_CPUS);
BPF_PERF_ARRAY(cache_misses, MAX_CPUS);
BPF_PERF_ARRAY(ref_cpu_cycles, MAX_CPUS);

// Stores accumulated metrics, waiting to hit a FEATURES Marker
BPF_HASH(complete_metrics, u64, struct resource_metrics, 32);  // TODO(Matt): Think about this size more
// Stores a snapshot of the metrics at START Marker, waiting to hit an END Marker
BPF_HASH(running_metrics, u64, struct resource_metrics, 32);  // TODO(Matt): Think about this size more

static u64 ou_key(const u32 ou, const s32 ou_instance) { return ((u64)ou) << 32 | ou_instance; }

static void metrics_accumulate(struct resource_metrics *const lhs, const struct resource_metrics *const rhs) {
  // never overwrite start_time or cpu_id
  lhs->end_time = rhs->end_time;  // always overwrite end_time
  SUBST_ACCUMULATE;
}
