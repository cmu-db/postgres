static struct tcp_sock *GetTCPSocketFromFD(const struct task_struct *const p, const int socket_fd) {
  struct files_struct *files = p->files;
  struct fdtable *fdt = files->fdt;
  struct file **fd_array = fdt->fd;
  struct file *fd_p = fd_array[socket_fd];
  struct socket *raw_socket = (struct socket *)fd_p->private_data;
  struct sock *raw_sock = raw_socket->sk;
  return (struct tcp_sock *)raw_sock;
}

// @see: https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
// bpf_perf_event_read_value normalization discussion
static u64 NormalizedPerfEventValue(const struct bpf_perf_event_value *const perf_event_value) {
  return perf_event_value->counter * perf_event_value->enabled / perf_event_value->running;
}

static bool cpu_start(struct resource_metrics *const metrics) {
  // read out counters
  const u32 cpu_k = bpf_get_smp_processor_id();
  struct bpf_perf_event_value perf_event_value = {};

  if (cpu_cycles.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  metrics->cpu_cycles = NormalizedPerfEventValue(&perf_event_value);

  if (instructions.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  metrics->instructions = NormalizedPerfEventValue(&perf_event_value);

  if (cache_references.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  metrics->cache_references = NormalizedPerfEventValue(&perf_event_value);

  if (cache_misses.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  metrics->cache_misses = NormalizedPerfEventValue(&perf_event_value);

  if (ref_cpu_cycles.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  metrics->ref_cpu_cycles = NormalizedPerfEventValue(&perf_event_value);

  return true;
}

static void disk_start(struct resource_metrics *const metrics, const struct task_struct *const p) {
  // disk metrics, limited to process-wide statistics
  metrics->disk_bytes_read = p->ioac.read_bytes;
  metrics->disk_bytes_written = p->ioac.write_bytes;
}

static void net_start(struct resource_metrics *const metrics, const struct task_struct *const p,
                      const int socket_fd_k) {
  const struct tcp_sock *const tcp_socket = GetTCPSocketFromFD(p, socket_fd_k);
  metrics->network_bytes_read = tcp_socket->copied_seq;  // don't want bytes_received, want unread
  metrics->network_bytes_written = tcp_socket->bytes_sent;
}

static bool cpu_end(struct resource_metrics *const metrics) {
  // read out counters and compute deltas
  const u32 cpu_k = bpf_get_smp_processor_id();
  struct bpf_perf_event_value perf_event_value = {};

  if (cpu_cycles.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  u64 end_value = NormalizedPerfEventValue(&perf_event_value);
  if (metrics->cpu_cycles > end_value) {
    return false;
  }
  metrics->cpu_cycles = end_value - metrics->cpu_cycles;

  if (instructions.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  end_value = NormalizedPerfEventValue(&perf_event_value);
  if (metrics->instructions > end_value) {
    return false;
  }
  metrics->instructions = end_value - metrics->instructions;

  if (cache_references.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  end_value = NormalizedPerfEventValue(&perf_event_value);
  if (metrics->cache_references > end_value) {
    return false;
  }
  metrics->cache_references = end_value - metrics->cache_references;

  if (cache_misses.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  end_value = NormalizedPerfEventValue(&perf_event_value);
  if (metrics->cache_misses > end_value) {
    return false;
  }
  metrics->cache_misses = end_value - metrics->cache_misses;

  if (ref_cpu_cycles.perf_counter_value(cpu_k, &perf_event_value, sizeof(perf_event_value)) < 0) {
    return false;
  }
  end_value = NormalizedPerfEventValue(&perf_event_value);
  if (metrics->ref_cpu_cycles > end_value) {
    return false;
  }
  metrics->ref_cpu_cycles = end_value - metrics->ref_cpu_cycles;

  metrics->cpu_id = cpu_k;

  return true;
}

static void disk_end(struct resource_metrics *const metrics, const struct task_struct *const p) {
  // disk metrics, limited to process-wide statistics
  metrics->disk_bytes_read = (p->ioac.read_bytes - metrics->disk_bytes_read);
  metrics->disk_bytes_written = (p->ioac.write_bytes - metrics->disk_bytes_written);
}

static void net_end(struct resource_metrics *const metrics, const struct task_struct *const p, const int socket_fd_k) {
  const struct tcp_sock *const tcp_socket = GetTCPSocketFromFD(p, socket_fd_k);
  metrics->network_bytes_read =
      tcp_socket->copied_seq - metrics->network_bytes_read;  // don't want bytes_received, want unread
  metrics->network_bytes_written = tcp_socket->bytes_sent - metrics->network_bytes_written;
}
