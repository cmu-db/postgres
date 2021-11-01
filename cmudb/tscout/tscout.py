#!/usr/bin/python3
import ctypes
import sys
import multiprocessing as mp
from dataclasses import dataclass
from typing import Callable, List, Tuple
from enum import Enum, unique
from bcc import BPF, utils, USDT, PerfType, PerfHWConfig
import setproctitle


@unique
class BPFType(str, Enum):
    u8 = "u8"
    u16 = "u16"
    u32 = "u32"
    u64 = "u64"


@dataclass
class BPFVariable:
    type: BPFType
    name: str


@dataclass
class OperatingUnit:
    operator: str
    function: str
    features: Tuple[BPFVariable]

    def name(self) -> str:
        return self.operator + '_' + self.function

    def begin_marker(self) -> str:
        return self.name() + '_begin'

    def end_marker(self) -> str:
        return self.name() + '_end'

    def features_marker(self) -> str:
        return self.name() + '_features'

    def features_struct(self) -> str:
        return ';\n'.join('{} {}'.format(column.type, column.name) for column in self.features) + ';'

    def features_columns(self) -> str:
        return ','.join(column.name for column in self.features)

    def serialize_features(self, output_event) -> str:
        return ','.join(str(getattr(output_event, column.name)) for column in self.features)


operating_units = (
    OperatingUnit("nodeAgg", "ExecAgg", ()),
    OperatingUnit("nodeAppend", "ExecAppend", ()),
    OperatingUnit("nodeCtescan", "ExecCteScan", ()),
    OperatingUnit("nodeCustom", "ExecCustomScan", ()),
    OperatingUnit("nodeForeignscan", "ExecForeignScan", ()),
    OperatingUnit("nodeFunctionscan", "ExecFunctionScan", ()),
    OperatingUnit("nodeGather", "ExecGather", ()),
    OperatingUnit("nodeGatherMerge", "ExecGatherMerge", ()),
    OperatingUnit("nodeGroup", "ExecGroup", ()),
    OperatingUnit("nodeHashjoin", "ExecHashJoinImpl", ()),
    OperatingUnit("nodeIncrementalSort", "ExecIncrementalSort", ()),
    OperatingUnit("nodeIndexonlyscan", "ExecIndexOnlyScan", ()),
    OperatingUnit("nodeIndexscan", "ExecIndexScan", ()),
    OperatingUnit("nodeLimit", "ExecLimit", ()),
    OperatingUnit("nodeLockRows", "ExecLockRows", ()),
    OperatingUnit("nodeMaterial", "ExecMaterial", ()),
    OperatingUnit("nodeMergeAppend", "ExecMergeAppend", ()),
    OperatingUnit("nodeMergejoin", "ExecMergeJoin", ()),
    OperatingUnit("nodeModifyTable", "ExecModifyTable", ()),
    OperatingUnit("nodeNamedtuplestorescan", "ExecNamedTuplestoreScan", ()),
    OperatingUnit("nodeNestloop", "ExecNestLoop", ()),
    OperatingUnit("nodeProjectSet", "ExecProjectSet", ()),
    OperatingUnit("nodeRecursiveunion", "ExecRecursiveUnion", ()),
    OperatingUnit("nodeResult", "ExecResult", ()),
    OperatingUnit("nodeSamplescan", "ExecSampleScan", ()),
    OperatingUnit("nodeSeqscan", "ExecSeqScan", ()),
    OperatingUnit("nodeSetOp", "ExecSetOp", ()),
    OperatingUnit("nodeSort", "ExecSort", ()),
    OperatingUnit("nodeSubplan", "ExecSubPlan", ()),
    OperatingUnit("nodeSubqueryscan", "ExecSubqueryScan", ()),
    OperatingUnit("nodeTableFuncscan", "ExecTableFuncScan", ()),
    OperatingUnit("nodeTidscan", "ExecTidScan", ()),
    OperatingUnit("nodeUnique", "ExecUnique", ()),
    OperatingUnit("nodeValuesscan", "ExecValuesScan", ()),
    OperatingUnit("nodeWindowAgg", "ExecWindowAgg", ()),
    OperatingUnit("nodeWorktablescan", "ExecWorkTableScan", ())
)

metrics = (
    BPFVariable(BPFType.u64, "start_time"),
    BPFVariable(BPFType.u64, "end_time"),
    BPFVariable(BPFType.u8, "cpu_id"),
    BPFVariable(BPFType.u64, "cpu_cycles"),
    BPFVariable(BPFType.u64, "instructions"),
    BPFVariable(BPFType.u64, "cache_references"),
    BPFVariable(BPFType.u64, "cache_misses"),
    BPFVariable(BPFType.u64, "ref_cpu_cycles"),
    BPFVariable(BPFType.u64, "network_bytes_read"),
    BPFVariable(BPFType.u64, "network_bytes_written"),
    BPFVariable(BPFType.u64, "disk_bytes_read"),
    BPFVariable(BPFType.u64, "disk_bytes_written"),
    BPFVariable(BPFType.u64, "memory_bytes"),
    BPFVariable(BPFType.u64, "elapsed_us")
)


def generate_markers(operation, ou_index):
    # Load the C code for the Markers.
    with open('markers.c', 'r') as markers_file:
        markers_c = markers_file.read()

    # Replace OU-specific placeholders in C code.
    markers_c = markers_c.replace("OU", operation.operator + '_' + operation.function)
    markers_c = markers_c.replace("FEATURES", operation.features_struct())
    markers_c = markers_c.replace("INDEX", str(ou_index))

    return markers_c


def collector(collector_flags, ou_processor_queues, pid, socket_fd):
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

    # Replace remaining placeholders in C code.
    metrics_struct = ';\n'.join('{} {}'.format(metric.type, metric.name) for metric in metrics) + ';'
    collector_c = collector_c.replace("METRICS", metrics_struct)
    num_cpus = len(utils.get_online_cpus())
    collector_c = collector_c.replace("MAX_CPUS", str(num_cpus))

    # Attach USDT probes to the target PID.
    collector_probes = USDT(pid=pid)
    for ou in operating_units:
        collector_probes.enable_probe(probe=ou.begin_marker(), fn_name=ou.begin_marker())
        collector_probes.enable_probe(probe=ou.end_marker(), fn_name=ou.end_marker())
        collector_probes.enable_probe(probe=ou.features_marker(), fn_name=ou.features_marker())

    # Load the BPF program, eliding setting socket fd if this pid won't generate network metrics.
    cflags = ['-DKBUILD_MODNAME="collector"']
    if socket_fd:
        cflags.append('-DCLIENT_SOCKET_FD={}'.format(socket_fd))
    collector_bpf = BPF(text=collector_c, usdt_contexts=[collector_probes], cflags=cflags)

    # open perf hardware events for BPF program
    collector_bpf["cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
    collector_bpf["instructions"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.INSTRUCTIONS)
    collector_bpf["cache_references"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CACHE_REFERENCES)
    collector_bpf["cache_misses"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CACHE_MISSES)
    collector_bpf["ref_cpu_cycles"].open_perf_event(PerfType.HARDWARE, PerfHWConfig.REF_CPU_CYCLES)

    output_buffer = 'collector_results'

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

    def collector_event(cpu, data, size):
        raw_data = collector_bpf[output_buffer].event(data)
        event_features = operating_units[raw_data.ou_index].serialize_features(raw_data)
        training_data = event_features + ',' + ','.join(
            str(getattr(raw_data, metric.name)) for metric in metrics) + '\n'
        ou_processor_queues[raw_data.ou_index].put(training_data)
        # heavy_hitter_update(raw_data.ou_index)

    # Open an output buffer this OU.
    collector_bpf[output_buffer].open_perf_buffer(callback=collector_event, lost_cb=lost_collector_event)

    print("Collector attached to PID {}.".format(pid))

    # Poll on the Collector's output buffer until Collector is shut down.
    while collector_flags[pid]:
        try:
            # Use a timeout to periodically check flag since polling the output buffer blocks.
            collector_bpf.perf_buffer_poll(1000)
        except KeyboardInterrupt:
            print("Collector for PID {} caught KeyboardInterrupt.".format(pid))
        except Exception as e:
            print("Collector for PID {} caught {}.".format(pid, e))

    print("Collector for PID {} shut down.".format(pid))


def lost_something(num_lost):
    pass


def processor(ou, buffered_strings):
    setproctitle.setproctitle("{} Processor".format(ou.name()))

    # Open output file, with the name based on the OU.
    file = open("./{}.csv".format(ou.name()), "w")

    # Write the OU's feature columns for CSV header, with an additional separator before resource metrics columns.
    file.write(ou.features_columns() + ',')

    # Write the resource metrics columns for the CSV header.
    file.write(','.join(metric.name for metric in metrics) + '\n')

    print("Processor started for {}.".format(ou.name()))

    try:
        # Write serialized training data points from shared queue to file.
        while True:
            string = buffered_strings.get()
            file.write(string)

    except KeyboardInterrupt:
        print("Processor for {} caught KeyboardInterrupt.".format(ou.name()))
        while True:
            # TScout is shutting down, write any remaining training data points.
            string = buffered_strings.get()
            if string is None:
                # Collectors have all shut down, and poison pill indicates there are no more training data points.
                print("Processor for {} received poison pill.".format(ou.name()))
                break
            file.write(string)
    except Exception as e:
        print("Processor for {} caught {}".format(ou.name(), e))
    finally:
        file.close()
        print("Processor for {} shut down.".format(ou.name()))


if __name__ == '__main__':
    # Parse the command line args, in this case just postmaster PID we're attaching to.
    if len(sys.argv) < 2:
        print("USAGE: tscout PID")
        exit()
    pid = sys.argv[1]

    setproctitle.setproctitle("{} TScout".format(pid))

    # Read the C code for TScout.
    with open('tscout.c', 'r') as tscout_file:
        tscout_c = tscout_file.read()

    # Attach USDT probes to the target PID.
    tscout_probes = USDT(pid=int(pid))
    tscout_probes.enable_probe(probe="postmaster_fork_backend", fn_name="postmaster_fork_backend")
    tscout_probes.enable_probe(probe="postmaster_fork_background", fn_name="postmaster_fork_background")
    tscout_probes.enable_probe(probe="postmaster_reap_backend", fn_name="postmaster_reap_backend")
    tscout_probes.enable_probe(probe="postmaster_reap_background", fn_name="postmaster_reap_background")

    # Load TScout program to monitor the Postmaster.
    tscout_bpf = BPF(text=tscout_c, usdt_contexts=[tscout_probes], cflags=['-DKBUILD_MODNAME="tscout"'])

    keep_running = True

    with mp.Manager() as manager:
        # Create coordination data structures for Collectors and Processors
        collector_flags = manager.dict()
        collector_processes = {}

        ou_processor_queues = []
        ou_processors = []

        # Create a Processor for each OU
        for ou in operating_units:
            # TODO(Matt): bound this queue size? may not work reliably with a poison pill for shutdown
            ou_processor_queue = mp.Queue()
            ou_processor_queues.append(ou_processor_queue)
            ou_processor = mp.Process(target=processor, args=(ou, ou_processor_queue,))
            ou_processor.start()
            ou_processors.append(ou_processor)


        def create_collector(child_pid, socket_fd):
            print("Postmaster forked PID {}, creating its Collector.".format(child_pid))
            collector_flags[child_pid] = True
            collector_process = mp.Process(target=collector,
                                           args=(collector_flags, ou_processor_queues, child_pid, socket_fd))
            collector_process.start()
            collector_processes[child_pid] = collector_process


        def destroy_collector(collector_process, child_pid):
            print("Postmaster reaped PID {}, destroying its Collector.".format(child_pid))
            collector_flags[child_pid] = False
            collector_process.join()
            del collector_flags[child_pid]
            del collector_processes[child_pid]


        def postmaster_event(cpu, data, size):
            output_event = tscout_bpf["postmaster_events"].event(data)
            event_type = output_event.type_
            child_pid = output_event.pid_
            if event_type == 0 or event_type == 1:
                create_collector(child_pid, output_event.socket_fd_ if event_type == 0 else None)
            elif event_type == 2 or event_type == 3:
                collector_process = collector_processes.get(child_pid)
                if collector_process:
                    destroy_collector(collector_process, child_pid)
            else:
                print("Unknown event type from Postmaster.")
                raise KeyboardInterrupt


        tscout_bpf["postmaster_events"].open_perf_buffer(callback=postmaster_event, lost_cb=lost_something)

        print("TScout attached to PID {}.".format(pid))

        # Poll on TScout's output buffer until TScout is shut down.
        while keep_running:
            try:
                tscout_bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                keep_running = False
            except Exception as e:
                print("TScout caught {}.".format(e))

        print("TScout shutting down.")

        # Shut down the Collectors so we don't generate any more data for the Processors.
        for pid, process in collector_processes.items():
            collector_flags[pid] = False
            process.join()
            print("Joined Collector for PID {}.".format(pid))
        print("TScout joined all Collectors.")

        # Shut down the Processor queues so everything gets flushed to the Processors.
        for ou_processor_queue in ou_processor_queues:
            ou_processor_queue.put(None)
            ou_processor_queue.close()
            ou_processor_queue.join_thread()
        print("TScout joined all Processor queues.")

        # Shut down the Processors once they're done writing any remaining data to disk.
        for ou_processor in ou_processors:
            ou_processor.join()
        print("TScout joined all Processors.")

        # We're done.
        exit()
