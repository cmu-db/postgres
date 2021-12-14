// SUBST_OU is replaced by the subsystem's name
struct SUBST_OU_features {
  SUBST_FEATURES;  // Replaced by a list of the features for this subsystem
};

struct SUBST_OU_output {
  u32 ou_index;
  SUBST_FEATURES;  // Replaced by a list of the features for this subsystem
  SUBST_METRICS;   // Replaced by the list of metrics
};

// Stores a snapshot of the metrics at START Marker, waiting to hit an END Marker
BPF_HASH(SUBST_OU_complete_features, s32, struct SUBST_OU_features, 32);  // TODO(Matt): Think about this size more
BPF_ARRAY(SUBST_OU_features_arr, struct SUBST_OU_features, 1);

static void SUBST_OU_reset(s32 ou_instance) {
  u64 key = ou_key(SUBST_INDEX, ou_instance);
  SUBST_OU_complete_features.delete(&ou_instance);
  complete_metrics.delete(&key);
  running_metrics.delete(&key);
}

void SUBST_OU_begin(struct pt_regs *ctx) {
  // TODO(Matt): Check running_features (NULL) or running_metrics (non-NULL) to see if our state machine is busted.
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  u64 key = ou_key(SUBST_INDEX, ou_instance);

  // Zero initialize start metrics
  struct resource_metrics metrics = {};

  // Probe for CPU counters
  if (!cpu_start(&metrics)) {
    SUBST_OU_reset(ou_instance);
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
  running_metrics.update(&key, &metrics);
}

void SUBST_OU_end(struct pt_regs *ctx) {
  // Retrieve start metrics
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  u64 key = ou_key(SUBST_INDEX, ou_instance);

  struct resource_metrics *metrics = NULL;
  metrics = running_metrics.lookup(&key);
  if (metrics == NULL) {
    SUBST_OU_reset(ou_instance);
    return;
  }

  if (metrics->end_time != 0) {
    // Arrived at the END marker out of order.
    SUBST_OU_reset(ou_instance);
    return;
  }

  // Collect an end time before probes are complete, converting from nanoseconds to microseconds
  metrics->end_time = (bpf_ktime_get_ns() >> 10);
  metrics->elapsed_us = (metrics->end_time - metrics->start_time);

  // Probe for CPU counters
  if (!cpu_end(metrics)) {
    SUBST_OU_reset(ou_instance);
    return;
  }
  struct task_struct *p = (struct task_struct *)bpf_get_current_task();
  disk_end(metrics, p);
#ifdef CLIENT_SOCKET_FD
  net_end(metrics, p, CLIENT_SOCKET_FD);
#endif

  // Store the completed metrics in the subsystem map, waiting for features
  struct resource_metrics *accumulated_metrics = NULL;
  accumulated_metrics = complete_metrics.lookup(&key);
  if (accumulated_metrics == NULL) {
    // They don't exist yet, but that's okay, this could be the first tuple. Just drop in the END instance's
    // metrics as the complete ones.
    complete_metrics.update(&key, metrics);
  } else {
    // We have accumulated metrics already. Let's add them.
    metrics_accumulate(accumulated_metrics, metrics);
  }

  running_metrics.delete(&key);
}

void SUBST_OU_features(struct pt_regs *ctx) {
  // TODO(Matt): Check complete_metrics (non-NULL) or running_metrics (non-NULL) to see if our state machine is busted.

  // Zero initialize output struct for features and metrics
  int idx = 0;
  struct SUBST_OU_features *features = SUBST_OU_features_arr.lookup(&idx);
  if (features == NULL) {
    // This should never happen and should be considered a fatal error.
    return;
  }
  memset(features, 0, sizeof(struct SUBST_OU_features));

  // Copy features from USDT arg (pointer to features struct in NoisePage) to output struct
  SUBST_READARGS

  // Store the start metrics in the subsystem map, waiting for end
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  SUBST_OU_complete_features.update(&ou_instance, features);
}

// A BPF array is defined because the OU output struct is typically larger
// than the 512 byte stack limit imposed by BPF.
BPF_ARRAY(SUBST_OU_output_arr, struct SUBST_OU_output, 1);
// A BPF perf output buffer is defined per OU because the labels being
// emitted are different for each OU. Previously, using only one perf output
// buffer resulted in using the labels of the last perf_submit caller in the
// source code, which was incorrect.
BPF_PERF_OUTPUT(collector_results_SUBST_INDEX);

void SUBST_OU_flush(struct pt_regs *ctx) {
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  u64 key = ou_key(SUBST_INDEX, ou_instance);

  struct resource_metrics *flush_metrics = NULL;
  flush_metrics = complete_metrics.lookup(&key);
  if (flush_metrics == NULL) {
    SUBST_OU_reset(ou_instance);
    return;
  }

  // Look up complete_features.
  // memcpy features into output_arr
  // memcpy flush_pointer into output_arr
  // Zero initialize output struct for features and metrics
  int idx = 0;
  struct SUBST_OU_output *output = SUBST_OU_output_arr.lookup(&idx);
  if (output == NULL) {
    // This should never happen and should be considered a fatal error.
    return;
  }
  memset(output, 0, sizeof(struct SUBST_OU_output));

  // Set the index of this SUBST_OU.
  output->ou_index = SUBST_INDEX;

  // Retrieve the features
  struct SUBST_OU_features *features = NULL;
  features = SUBST_OU_complete_features.lookup(&ou_instance);
  if (features == NULL) {
    SUBST_OU_reset(ou_instance);
    return;
  }

  // Copy completed features to output struct
  __builtin_memcpy(&(output->SUBST_FIRST_FEATURE), features, sizeof(struct SUBST_OU_features));

  // Copy completed metrics to output struct
  __builtin_memcpy(&(output->SUBST_FIRST_METRIC), flush_metrics, sizeof(struct resource_metrics));

  // The SUBST_OU_output_arr does not need to be deleted because it is memset to 0 every time.

  // Send output struct to userspace via subsystem's perf ring buffer
  collector_results_SUBST_INDEX.perf_submit(ctx, output, sizeof(struct SUBST_OU_output));
  SUBST_OU_reset(ou_instance);
}