#!/usr/bin/python3
import multiprocessing as mp
import sys

from dataclasses import dataclass
import psutil
import setproctitle
import logging
from bcc import BPF, USDT, PerfHWConfig, PerfType, utils

import model


@dataclass
class PostgresInstance:
    """Finds and then stashes the PIDs for a postgres instance designated by the constructor's pid argument."""

    def __init__(self, pid):

        def cmd_in_cmdline(cmd, proc):
            """

            Parameters
            ----------
            cmd: str
            proc: psutil.Process

            Returns
            -------
            True if the provided command was in the provided Process' command line args.
            """
            return any(cmd in x for x in proc.cmdline())

        self.postgres_pid = pid
        try:
            # Iterate through all the children for the given PID, and extract PIDs for expected background workers.
            for child in psutil.Process(self.postgres_pid).children():
                if not self.checkpointer_pid and cmd_in_cmdline('checkpointer', child):
                    self.checkpointer_pid = child.pid
                elif not self.bgwriter_pid and cmd_in_cmdline('background', child) and cmd_in_cmdline('writer', child):
                    self.bgwriter_pid = child.pid
                elif not self.walwriter_pid and cmd_in_cmdline('walwriter', child):
                    self.walwriter_pid = child.pid
                elif all(x is not None for x in [self.checkpointer_pid, self.bgwriter_pid, self.walwriter_pid]):
                    # We found all the children PIDs that we care about, so we're done.
                    return
        except psutil.NoSuchProcess:
            logger.error("Provided PID not found.")
            exit()

        if any(x is None for x in [self.checkpointer_pid, self.bgwriter_pid, self.walwriter_pid]):
            # TODO(Matt): maybe get fancy with dataclasses.fields() so we don't have to keep adding to this if more
            #  fields are added to the dataclass?
            logger.error("Did not find expected background workers for provided PID.")
            exit()

    postgres_pid: int = None
    checkpointer_pid: int = None
    bgwriter_pid: int = None
    walwriter_pid: int = None


logger = logging.getLogger('tscout')

# Set up the OUs and metrics to be collected.
modeler = model.Model()
operating_units = modeler.operating_units
metrics = modeler.metrics

# OUs may have common structs that cause duplicate struct definitions in
# the collector_c file that is generated, e.g., struct Plan.
# helper_struct_defs is used to avoid duplicate struct definitions by
# accumulating all the struct definitions exactly once, and defining those
# structs at one shot at the start of the generated collector_c file.
helper_struct_defs = {}


def generate_readargs(feature_list):
    """
    Generate bpf_usdt_readargs_p() calls for the given feature list.

    This function assumes that the following are in scope:
    - struct pt_regs *ctx
    - struct SUBST_OU_output *output

    Parameters
    ----------
    feature_list : List[model.Feature]
        List of BPF features being emitted.

    Returns
    -------
    code : str
        bpf_usdt_readarg() and bpf_usdt_readarg_p() invocations.
    """
    code = []
    non_feature_usdt_args = 1  # Currently just plan_node_id. If any other non-feature args are added, increment this.
    for idx, feature in enumerate(feature_list, 1):
        first_member = feature.bpf_tuple[0].name
        if feature.readarg_p:
            readarg_p = ['  bpf_usdt_readarg_p(',
                         f'{idx + non_feature_usdt_args}, ',
                         'ctx, ',
                         f'&(features->{first_member}), ',
                         f'sizeof(struct DECL_{feature.name})',
                         ');\n']
            code.append(''.join(readarg_p))
        else:
            readarg = ['  bpf_usdt_readarg(',
                       f'{idx + non_feature_usdt_args}, ',
                       'ctx, ',
                       f'&(features->{first_member})',
                       ');\n']
            code.append(''.join(readarg))
    return ''.join(code)


def generate_markers(operation, ou_index):
    global helper_struct_defs
    # Load the C code for the Markers.
    with open('markers.c', 'r') as markers_file:
        markers_c = markers_file.read()

    # Replace OU-specific placeholders in C code.
    markers_c = markers_c.replace("SUBST_OU",
                                  f'{operation.function}')
    markers_c = markers_c.replace("SUBST_READARGS",
                                  generate_readargs(operation.features_list))
    markers_c = markers_c.replace("SUBST_FEATURES",
                                  operation.features_struct())
    markers_c = markers_c.replace("SUBST_INDEX",
                                  str(ou_index))
    markers_c = markers_c.replace("SUBST_FIRST_FEATURE",
                                  operation.features_list[0].bpf_tuple[0].name)

    # Accumulate struct definitions.
    helper_struct_defs = {**helper_struct_defs, **operation.helper_structs()}

    return markers_c


def collector(collector_flags, ou_processor_queues, pid, socket_fd):
    global helper_struct_defs
    setproctitle.setproctitle("{} Collector".format(pid))

    # Read the C code for the Collector.
    with open('collector.c', 'r') as collector_file:
        collector_c = collector_file.read()
    # Append the C code for the Probes.
    with open('probes.c', 'r') as probes_file:
        collector_c += probes_file.read()
    # Append the C code for the Markers.
    for ou_index, ou in enumerate(operating_units):
        collector_c += generate_markers(ou, ou_index)
    # Prepend the helper struct defs.
    collector_c = '\n'.join(helper_struct_defs.values()) + '\n' + collector_c

    # Replace remaining placeholders in C code.
    defs = ['{} {}'.format(metric.bpf_type, metric.name) for metric in metrics]
    metrics_struct = ';\n'.join(defs) + ';'
    collector_c = collector_c.replace("SUBST_METRICS", metrics_struct)
    accumulate = ['lhs->{} += rhs->{}'.format(metric.name, metric.name) for metric in metrics if
                  metric.name not in ('start_time', 'end_time', 'cpu_id')]  # don't accumulate these 3 metrics
    metrics_accumulate = ';\n'.join(accumulate) + ';'
    collector_c = collector_c.replace("SUBST_ACCUMULATE", metrics_accumulate)
    collector_c = collector_c.replace("SUBST_FIRST_METRIC", metrics[0].name)

    num_cpus = len(utils.get_online_cpus())
    collector_c = collector_c.replace("MAX_CPUS", str(num_cpus))

    # Attach USDT probes to the target PID.
    collector_probes = USDT(pid=pid)
    for ou in operating_units:
        for probe in [ou.features_marker(), ou.begin_marker(), ou.end_marker(), ou.flush_marker()]:
            collector_probes.enable_probe(probe=probe, fn_name=probe)

    # Load the BPF program, eliding setting the socket fd
    # if this pid won't generate network metrics.
    cflags = ['-DKBUILD_MODNAME="collector"']
    if socket_fd:
        cflags.append('-DCLIENT_SOCKET_FD={}'.format(socket_fd))

    collector_bpf = BPF(text=collector_c,
                        usdt_contexts=[collector_probes],
                        cflags=cflags)

    # open perf hardware events for BPF program
    collector_bpf["cpu_cycles"].open_perf_event(
        PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
    collector_bpf["instructions"].open_perf_event(
        PerfType.HARDWARE, PerfHWConfig.INSTRUCTIONS)
    collector_bpf["cache_references"].open_perf_event(
        PerfType.HARDWARE, PerfHWConfig.CACHE_REFERENCES)
    collector_bpf["cache_misses"].open_perf_event(
        PerfType.HARDWARE, PerfHWConfig.CACHE_MISSES)
    collector_bpf["ref_cpu_cycles"].open_perf_event(
        PerfType.HARDWARE, PerfHWConfig.REF_CPU_CYCLES)

    heavy_hitter_ou_index = -1
    heavy_hitter_counter = 0

    def heavy_hitter_update(ou_index):
        nonlocal heavy_hitter_counter
        nonlocal heavy_hitter_ou_index

        if heavy_hitter_counter == 0:
            heavy_hitter_ou_index = ou_index
            heavy_hitter_counter = 1
        else:
            if heavy_hitter_ou_index == ou_index:
                heavy_hitter_counter = heavy_hitter_counter + 1
            else:
                heavy_hitter_counter = heavy_hitter_counter - 1

    def lost_collector_event(num_lost):
        pass

    def collector_event_builder(output_buffer):
        def collector_event(cpu, data, size):
            raw_data = collector_bpf[output_buffer].event(data)
            operating_unit = operating_units[raw_data.ou_index]
            event_features = operating_unit.serialize_features(
                raw_data)  # TODO(Matt): consider moving serialization to CSV string to Processor
            training_data = ''.join([
                event_features,
                ',',
                ','.join(metric.serialize(raw_data)
                         for metric in metrics),
                '\n'
            ])
            ou_processor_queues[raw_data.ou_index].put(training_data)  # TODO(Matt): maybe put_nowait?
            # heavy_hitter_update(raw_data.ou_index)

        return collector_event

    # Open an output buffer for this OU.
    for i in range(len(operating_units)):
        output_buffer = f'collector_results_{i}'
        collector_bpf[output_buffer].open_perf_buffer(
            callback=collector_event_builder(output_buffer),
            lost_cb=lost_collector_event)

    logger.info("Collector attached to PID {}.".format(pid))

    # Poll on the Collector's output buffer until Collector is shut down.
    while collector_flags[pid]:
        try:
            # Use a timeout to periodically check the flag
            # since polling the output buffer blocks.
            collector_bpf.perf_buffer_poll(1000)
        except KeyboardInterrupt:
            logger.info("Collector for PID {} caught KeyboardInterrupt.".format(pid))
        except Exception as e:
            logger.warning("Collector for PID {} caught {}.".format(pid, e))

    logger.info("Collector for PID {} shut down.".format(pid))


def lost_something(num_lost):
    pass


def processor(ou, buffered_strings):
    setproctitle.setproctitle("{} Processor".format(ou.name()))

    # Open output file, with the name based on the OU.
    file = open("./{}.csv".format(ou.name()), "w")

    # Write the OU's feature columns for CSV header,
    # with an additional separator before resource metrics columns.
    file.write(ou.features_columns() + ',')

    # Write the resource metrics columns for the CSV header.
    file.write(','.join(metric.name for metric in metrics) + '\n')

    logger.info("Processor started for {}.".format(ou.name()))

    try:
        # Write serialized training data points from shared queue to file.
        while True:
            string = buffered_strings.get()
            file.write(string)

    except KeyboardInterrupt:
        logger.info("Processor for {} caught KeyboardInterrupt.".format(ou.name()))
        while True:
            # TScout is shutting down.
            # Write any remaining training data points.
            string = buffered_strings.get()
            if string is None:
                # Collectors have all shut down, and poison pill
                # indicates there are no more training data points.
                logger.info(f"Processor for {ou.name()} received poison pill.")
                break
            file.write(string)
    except Exception as e:
        logger.warning("Processor for {} caught {}".format(ou.name(), e))
    finally:
        file.close()
        logger.info("Processor for {} shut down.".format(ou.name()))


if __name__ == '__main__':
    # Parse the command line args, in this case,
    # just the postmaster PID that we're attaching to.
    if len(sys.argv) < 2:
        logger.error("USAGE: tscout PID")
        exit()
    pid = int(sys.argv[1])

    postgres = PostgresInstance(pid)

    setproctitle.setproctitle("{} TScout".format(postgres.postgres_pid))

    # Read the C code for TScout.
    with open('tscout.c', 'r') as tscout_file:
        tscout_c = tscout_file.read()

    # Attach USDT probes to the target PID.
    tscout_probes = USDT(pid=postgres.postgres_pid)
    for probe in ['fork_backend', 'fork_background',
                  'reap_backend', 'reap_background']:
        tscout_probes.enable_probe(probe=probe, fn_name=probe)

    # Load TScout program to monitor the Postmaster.
    tscout_bpf = BPF(text=tscout_c,
                     usdt_contexts=[tscout_probes],
                     cflags=['-DKBUILD_MODNAME="tscout"'])

    keep_running = True

    with mp.Manager() as manager:
        # Create coordination data structures for Collectors and Processors
        collector_flags = manager.dict()
        collector_processes = {}

        ou_processor_queues = []
        ou_processors = []

        # Create a Processor for each OU
        for ou in operating_units:
            # TODO(Matt): maybe bound this queue size?
            #  may not work reliably with a poison pill for shutdown
            ou_processor_queue = mp.Queue()
            ou_processor_queues.append(ou_processor_queue)
            ou_processor = mp.Process(target=processor,
                                      args=(ou, ou_processor_queue,))
            ou_processor.start()
            ou_processors.append(ou_processor)


        def create_collector(child_pid, socket_fd):
            logger.info(f"Postmaster forked PID {child_pid}, "
                        f"creating its Collector.")
            collector_flags[child_pid] = True
            collector_process = mp.Process(
                target=collector,
                args=(collector_flags,
                      ou_processor_queues,
                      child_pid,
                      socket_fd))
            collector_process.start()
            collector_processes[child_pid] = collector_process


        def destroy_collector(collector_process, child_pid):
            logger.info(f"Postmaster reaped PID {child_pid}, "
                        f"destroying its Collector.")
            collector_flags[child_pid] = False
            collector_process.join()
            del collector_flags[child_pid]
            del collector_processes[child_pid]


        def postmaster_event(cpu, data, size):
            output_event = tscout_bpf["postmaster_events"].event(data)
            event_type = output_event.type_
            child_pid = output_event.pid_
            if event_type == 0 or event_type == 1:
                fd = output_event.socket_fd_ if event_type == 0 else None
                create_collector(child_pid, fd)
            elif event_type == 2 or event_type == 3:
                collector_process = collector_processes.get(child_pid)
                if collector_process:
                    destroy_collector(collector_process, child_pid)
            else:
                logger.error("Unknown event type from Postmaster.")
                raise KeyboardInterrupt


        tscout_bpf["postmaster_events"].open_perf_buffer(
            callback=postmaster_event, lost_cb=lost_something)

        print("TScout attached to PID {}.".format(postgres.postgres_pid))

        # Poll on TScout's output buffer until TScout is shut down.
        while keep_running:
            try:
                tscout_bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                keep_running = False
            except Exception as e:
                logger.warning("TScout caught {}.".format(e))

        print("TScout shutting down.")

        # Shut down the Collectors so that
        # no more data is generated for the Processors.
        for pid, process in collector_processes.items():
            collector_flags[pid] = False
            process.join()
            logger.info("Joined Collector for PID {}.".format(pid))
        print("TScout joined all Collectors.")

        # Shut down the Processor queues so that
        # everything gets flushed to the Processors.
        for ou_processor_queue in ou_processor_queues:
            ou_processor_queue.put(None)
            ou_processor_queue.close()
            ou_processor_queue.join_thread()
        print("TScout joined all Processor queues.")

        # Shut down the Processors once the Processors are done
        # writing any remaining data to disk.
        for ou_processor in ou_processors:
            ou_processor.join()
        print("TScout joined all Processors.")
        print("TScout for PID {} shut down.".format(postgres.postgres_pid))
        # We're done.
        exit()
