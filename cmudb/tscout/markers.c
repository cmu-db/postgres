// OU is replaced by the subsystem's name
struct OU_features {
  FEATURES  // Replaced by a list of the features for this subsystem
};

struct OU_output {
  u32 ou_index;
  FEATURES  // Replaced by a list of the features for this subsystem
  METRICS  // Replaced by the list of metrics
};

void OU_begin(struct pt_regs *ctx) {
  // Zero initialize start metrics
  struct resource_metrics metrics = {};

  // Probe for CPU counters
  if (!cpu_start(&metrics)) {
    return;
  }
  struct task_struct *p = (struct task_struct *)bpf_get_current_task();
  disk_start(&metrics, p);
#ifdef CLIENT_SOCKET_FD
  net_start(&metrics, p, CLIENT_SOCKET_FD);
#endif

  // Collect a start time after probes are complete, converting from nanoseconds to microseconds
  metrics.start_time = (bpf_ktime_get_ns() >> 10);

  // Store the start metrics in the subsystem map, waiting for end
  u32 ou_k = INDEX;
  incomplete_metrics.update(&ou_k, &metrics);
}

void OU_end(struct pt_regs *ctx) {
  // Retrieve start metrics
  struct resource_metrics *metrics = NULL;
  u32 ou_k = INDEX;
  metrics = incomplete_metrics.lookup(&ou_k);
  if (metrics == NULL) {
    return;
  }

  if (metrics->end_time != 0) {
    incomplete_metrics.delete(&ou_k);
    return;
  }

  // Collect an end time before probes are complete, converting from nanoseconds to microseconds
  metrics->end_time = (bpf_ktime_get_ns() >> 10);
  metrics->elapsed_us = (metrics->end_time - metrics->start_time);

  // Probe for CPU counters
  if (!cpu_end(metrics)) {
    incomplete_metrics.delete(&ou_k);
    return;
  }
  struct task_struct *p = (struct task_struct *)bpf_get_current_task();
  disk_end(metrics, p);
#ifdef CLIENT_SOCKET_FD
  net_end(metrics, p, CLIENT_SOCKET_FD);
#endif

  // Store the completed metrics in the subsystem map, waiting for features
  incomplete_metrics.update(&ou_k, metrics);
}

void OU_features(struct pt_regs *ctx) {
  // Retrieve completed metrics
  struct resource_metrics *metrics = NULL;
  u32 ou_k = INDEX;
  metrics = incomplete_metrics.lookup(&ou_k);
  if (metrics == NULL) {
    return;
  }

  // Zero initialize output struct for features and metrics
  struct OU_output output = { .ou_index = INDEX };

  // Copy completed metrics to output struct
  __builtin_memcpy(&(output.start_time), metrics, sizeof(struct resource_metrics));

  // Copy features from USDT arg (pointer to features struct in NoisePage) to output struct
  // bpf_usdt_readarg_p(1, ctx, &output, sizeof(struct OU_features));

  incomplete_metrics.delete(&ou_k);

  // Send output struct to userspace via subsystem's perf ring buffer
  collector_results.perf_submit(ctx, &output, sizeof(struct OU_output));
}
