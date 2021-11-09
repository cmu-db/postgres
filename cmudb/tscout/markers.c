// SUBST_OU is replaced by the subsystem's name
struct SUBST_OU_features {
  SUBST_FEATURES  // Replaced by a list of the features for this subsystem
};

struct SUBST_OU_output {
  u32 ou_index;
  SUBST_FEATURES  // Replaced by a list of the features for this subsystem
      METRICS     // Replaced by the list of metrics
};

void SUBST_OU_begin(struct pt_regs *ctx) {
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
  u32 ou_k = SUBST_INDEX;
  s32 plan_node_id;
  bpf_usdt_readarg(1, ctx, &plan_node_id);
  u64 key = incomplete_metrics_key(ou_k, plan_node_id);
  incomplete_metrics.update(&key, &metrics);
}

void SUBST_OU_end(struct pt_regs *ctx) {
  // Retrieve start metrics
  struct resource_metrics *metrics = NULL;
  u32 ou_k = SUBST_INDEX;
  s32 plan_node_id;
  bpf_usdt_readarg(1, ctx, &plan_node_id);
  u64 key = incomplete_metrics_key(ou_k, plan_node_id);
  metrics = incomplete_metrics.lookup(&key);
  if (metrics == NULL) {
    return;
  }

  if (metrics->end_time != 0) {
    // Arrived at the END marker out of order.
    incomplete_metrics.delete(&key);
    return;
  }

  // Collect an end time before probes are complete, converting from nanoseconds to microseconds
  metrics->end_time = (bpf_ktime_get_ns() >> 10);
  metrics->elapsed_us = (metrics->end_time - metrics->start_time);

  // Probe for CPU counters
  if (!cpu_end(metrics)) {
    incomplete_metrics.delete(&key);
    return;
  }
  struct task_struct *p = (struct task_struct *)bpf_get_current_task();
  disk_end(metrics, p);
#ifdef CLIENT_SOCKET_FD
  net_end(metrics, p, CLIENT_SOCKET_FD);
#endif

  // Store the completed metrics in the subsystem map, waiting for features
  incomplete_metrics.update(&key, metrics);
}

// A BPF array is defined because the OU output struct is typically larger
// than the 512 byte stack limit imposed by BPF.
BPF_ARRAY(SUBST_OU_output_arr, struct SUBST_OU_output, 1);
// A BPF perf output buffer is defined per OU because the labels being
// emitted are different for each OU. Previously, using only one perf output
// buffer resulted in using the labels of the last perf_submit caller in the
// source code, which was incorrect.
BPF_PERF_OUTPUT(collector_results_SUBST_INDEX);

void SUBST_OU_features(struct pt_regs *ctx) {
  // Retrieve completed metrics
  struct resource_metrics *metrics = NULL;
  u32 ou_k = SUBST_INDEX;
  s32 plan_node_id;
  bpf_usdt_readarg(1, ctx, &plan_node_id);
  u64 key = incomplete_metrics_key(ou_k, plan_node_id);
  metrics = incomplete_metrics.lookup(&key);
  if (metrics == NULL || metrics->end_time == 0) {
    // Arrived at the FEATURES marker out of order.
    return;
  }

  // Zero initialize output struct for features and metrics
  int idx = 0;
  struct SUBST_OU_output *output = SUBST_OU_output_arr.lookup(&idx);
  if (output == NULL) {
    return;
  }
  memset(output, 0, sizeof(struct SUBST_OU_output));

  // Set the index of this SUBST_OU.
  output->ou_index = SUBST_INDEX;

  // Copy completed metrics to output struct
  __builtin_memcpy(&(output->start_time), metrics, sizeof(struct resource_metrics));

  // Copy features from USDT arg (pointer to features struct in NoisePage) to output struct
  SUBST_READARGS

  // This enforces the state machine of begin -> end -> features.
  incomplete_metrics.delete(&key);
  // The SUBST_OU_output_arr does not need to be deleted because it is memset to 0 every time.

  // Send output struct to userspace via subsystem's perf ring buffer
  collector_results_SUBST_INDEX.perf_submit(ctx, output, sizeof(struct SUBST_OU_output));
}