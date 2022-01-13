// SUBST_OU is replaced by the subsystem's name
struct SUBST_OU_features {
  SUBST_FEATURES;  // Replaced by a list of the features for this subsystem
};

struct SUBST_OU_output {
  u32 ou_index;
  SUBST_FEATURES;  // Replaced by a list of the features for this subsystem
  SUBST_METRICS;   // Replaced by the list of metrics
};

// Stores features for a training data point, waiting for BEGIN, END, and FLUSH.
BPF_HASH(SUBST_OU_complete_features, s32, struct SUBST_OU_features, 32);  // TODO(Matt): Think about this size more
// We can't assume that a features struct will fit on the stack, so we allocate an array of size 1 to use as scratch.
BPF_ARRAY(SUBST_OU_features_arr, struct SUBST_OU_features, 1);

// Reset the state of this OU instance. This is a general purpose function to call if the Marker state machine won't
// yield a valid data point.
static void SUBST_OU_reset(s32 ou_instance) {
  u64 key = ou_key(SUBST_INDEX, ou_instance);
  SUBST_OU_complete_features.delete(&ou_instance);
  complete_metrics.delete(&key);
  running_metrics.delete(&key);
}

void SUBST_OU_begin(struct pt_regs *ctx) {
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  u64 key = ou_key(SUBST_INDEX, ou_instance);

  // Zero initialize start metrics
  struct resource_metrics metrics = {};

  // Probe for CPU counters
  if (!cpu_start(&metrics)) {
    // This shouldn't happen, but best to handle failing to read PMC registers here and toss the data point.
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

  // Store the start metrics in the map, waiting for END.
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

  // TODO(Matt): Consider snapshotting end metrics before doing any other work in this Marker. I don't think work before
  // this is enough to greatly alter measurements, but if it gets any more complicated...

  // Collect an end time before probes are complete, converting from nanoseconds to microseconds.
  metrics->end_time = (bpf_ktime_get_ns() >> 10);
  metrics->elapsed_us = (metrics->end_time - metrics->start_time);

  // Probe for CPU counters
  if (!cpu_end(metrics)) {
    // This shouldn't happen, but best to handle failing to read PMC registers here and toss the data point.
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
    // We don't have any accumulated metrics. Use these metrics as the complete metrics.
    complete_metrics.update(&key, metrics);
  } else {
    // We have accumulated metrics already. Let's add these metrics to them.
    metrics_accumulate(accumulated_metrics, metrics);
  }

  running_metrics.delete(&key);
}

void SUBST_OU_features(struct pt_regs *ctx) {
  // Fetch scratch features struct
  int idx = 0;
  struct SUBST_OU_features *features = SUBST_OU_features_arr.lookup(&idx);
  if (features == NULL) {
    bpf_trace_printk("Fatal error. Scratch array lookup failed.");
    return;
  }
  memset(features, 0, sizeof(struct SUBST_OU_features));

  // Copy features from USDT arg (pointer to features struct in NoisePage) to features struct.
  SUBST_READARGS;

  // Store the features, waiting for BEGIN(s), END(s), and FLUSH.
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  SUBST_OU_complete_features.update(&ou_instance, features);
}

// We can't assume that an output struct will fit on the stack, so we allocate an array of size 1 to use as scratch.
BPF_ARRAY(SUBST_OU_output_arr, struct SUBST_OU_output, 1);
// A BPF perf output buffer is defined per OU because the labels being emitted are different for each OU. We can't mix
// the structs being passed through this buffer, and since each OU is different we need unique buffer.
BPF_PERF_OUTPUT(collector_results_SUBST_INDEX);

void SUBST_OU_flush(struct pt_regs *ctx) {
  s32 ou_instance = 0;
  bpf_usdt_readarg(1, ctx, &ou_instance);
  u64 key = ou_key(SUBST_INDEX, ou_instance);

  // Retrieve the features.
  struct SUBST_OU_features *features = NULL;
  features = SUBST_OU_complete_features.lookup(&ou_instance);
  if (features == NULL) {
    // We don't have any features for this data point.
    SUBST_OU_reset(ou_instance);
    return;
  }

  struct resource_metrics *flush_metrics = NULL;
  flush_metrics = complete_metrics.lookup(&key);
  if (flush_metrics == NULL) {
    // We don't have any metrics for this data point.
    SUBST_OU_reset(ou_instance);
    return;
  }

  // Fetch scratch output struct.
  int idx = 0;
  struct SUBST_OU_output *output = SUBST_OU_output_arr.lookup(&idx);
  if (output == NULL) {
    bpf_trace_printk("Fatal error. Scratch array lookup failed.");
    return;
  }
  // Zero initialize output struct for features and metrics.
  memset(output, 0, sizeof(struct SUBST_OU_output));

  // Copy features to output struct.
  __builtin_memcpy(&(output->SUBST_FIRST_FEATURE), features, sizeof(struct SUBST_OU_features));

  // Copy completed metrics to output struct.
  __builtin_memcpy(&(output->SUBST_FIRST_METRIC), flush_metrics, sizeof(struct resource_metrics));

  // Set the index of this SUBST_OU so the Collector knows which Processor to send this data point to.
  output->ou_index = SUBST_INDEX;
  // Set remaining metadata.
  output->pid = bpf_get_current_pid_tgid();

  // Send output struct to userspace via subsystem's perf ring buffer.
  collector_results_SUBST_INDEX.perf_submit(ctx, output, sizeof(struct SUBST_OU_output));
  SUBST_OU_reset(ou_instance);
}