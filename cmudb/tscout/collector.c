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

// Each OU gets its own ou_id->metrics for incomplete data
BPF_HASH(incomplete_metrics, u32, struct resource_metrics);
