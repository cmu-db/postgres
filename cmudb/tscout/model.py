"""
model.py

Convert C types to BPF types.
Define the Operating Units (OUs) and metrics to be collected.
"""

import logging
import struct
import sys
from dataclasses import dataclass
from enum import Enum, unique
from typing import List, Mapping, Tuple

import clang.cindex

import clang_parser

logger = logging.getLogger('tscout')


@unique
class BPFType(str, Enum):
    """BPF only has signed and unsigned integers."""
    i8 = "s8"
    i16 = "s16"
    i32 = "s32"
    i64 = "s64"
    u8 = "u8"
    u16 = "u16"
    u32 = "u32"
    u64 = "u64"
    pointer = "void *"


@dataclass
class BPFVariable:
    name: str
    c_type: clang.cindex.TypeKind
    alignment: int = None  # Non-None for the first field of a struct, using alignment value of the struct.

    def alignment_string(self):
        return ' __attribute__ ((aligned ({})))'.format(self.alignment) if self.alignment is not None else ''

    def should_output(self):
        """
        Return whether this variable should be included in Processor output.

        Returns
        -------
        True if the variable should be output. False otherwise.
        Some variables should not be output, e.g., pointers,
        as the values do not make sense from a ML perspective.
        """
        suppressed = [
            clang.cindex.TypeKind.POINTER,
            clang.cindex.TypeKind.FUNCTIONPROTO,
            clang.cindex.TypeKind.INCOMPLETEARRAY,
            clang.cindex.TypeKind.CONSTANTARRAY,
        ]
        return self.c_type not in suppressed

    def serialize(self, output_event):
        """
        Serialize this variable given the output event containing its value.

        Parameters
        ----------
        output_event
            The perf output event that contains the output value for this var.

        Returns
        -------
        val : str
            The serialized value of this variable.
        """
        if self.c_type == clang.cindex.TypeKind.FLOAT:
            return str(struct.unpack('f', getattr(output_event, self.name).to_bytes(4, byteorder=sys.byteorder))[0])
        elif self.c_type == clang.cindex.TypeKind.DOUBLE:
            return str(struct.unpack('d', getattr(output_event, self.name).to_bytes(8, byteorder=sys.byteorder))[0])
        else:
            return str(getattr(output_event, self.name))


# Map from Clang type kinds to BPF types.
CLANG_TO_BPF = {
    clang.cindex.TypeKind.BOOL: BPFType.u8,
    clang.cindex.TypeKind.CHAR_U: BPFType.u8,
    clang.cindex.TypeKind.UCHAR: BPFType.u8,
    clang.cindex.TypeKind.USHORT: BPFType.u16,
    clang.cindex.TypeKind.UINT: BPFType.u32,
    clang.cindex.TypeKind.ULONG: BPFType.u64,
    clang.cindex.TypeKind.ULONGLONG: BPFType.u64,
    clang.cindex.TypeKind.CHAR_S: BPFType.i8,
    clang.cindex.TypeKind.SCHAR: BPFType.i8,
    clang.cindex.TypeKind.SHORT: BPFType.i16,
    clang.cindex.TypeKind.INT: BPFType.i32,
    clang.cindex.TypeKind.LONG: BPFType.i64,
    clang.cindex.TypeKind.LONGLONG: BPFType.i64,
    clang.cindex.TypeKind.FLOAT: BPFType.u32,
    clang.cindex.TypeKind.DOUBLE: BPFType.u64,
    clang.cindex.TypeKind.ENUM: BPFType.i32,
    clang.cindex.TypeKind.POINTER: BPFType.pointer,
    clang.cindex.TypeKind.FUNCTIONPROTO: BPFType.pointer,
    clang.cindex.TypeKind.INCOMPLETEARRAY: BPFType.pointer,
    clang.cindex.TypeKind.CONSTANTARRAY: BPFType.pointer,
}


@dataclass
class Feature:
    """
    A feature in the model.

    name : str
        The name of the feature.
    readarg_p : bool
        True if bpf_usdt_readarg_p should be used.
        False if bpf_usdt_readarg should be used.
    bpf_tuple : Tuple[BPFVariable]
        A tuple of all the BPF-typed variables that comprise this feature. First entry should have an alignment.
    """
    name: str
    readarg_p: bool = None
    bpf_tuple: Tuple[BPFVariable] = None


QUERY_ID = Feature("QueryId", readarg_p=False, bpf_tuple=(BPFVariable("query_id", clang.cindex.TypeKind.ULONG),))
LEFT_CHILD_NODE_ID = Feature("left_child_plan_node_id", readarg_p=False,
                             bpf_tuple=(BPFVariable("left_child_plan_node_id", clang.cindex.TypeKind.INT),))
RIGHT_CHILD_NODE_ID = Feature("right_child_plan_node_id", readarg_p=False,
                              bpf_tuple=(BPFVariable("right_child_plan_node_id", clang.cindex.TypeKind.INT),))

"""
An OU is specified via (operator, postgres_function, feature_types).

operator : str
    The name of the PostgreSQL operator.
postgres_function : str
    The name of the PostgreSQL function generating the features marker.
feature_types : List[Feature]
    A list of the features being emitted by PostgreSQL.
    If you modify this list, you must change the markers in PostgreSQL source.
"""
OU_DEFS = [
    ("ExecAgg",
     [
         QUERY_ID,
         Feature("Agg"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecAppend",
     [
         QUERY_ID,
         Feature("Append"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecCteScan",
     [
         QUERY_ID,
         Feature("CteScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecCustomScan",
     [
         QUERY_ID,
         Feature("CustomScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecForeignScan",
     [
         QUERY_ID,
         Feature("ForeignScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecFunctionScan",
     [
         QUERY_ID,
         Feature("FunctionScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecGather",
     [
         QUERY_ID,
         Feature("Gather"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecGatherMerge",
     [
         QUERY_ID,
         Feature("GatherMerge"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecGroup",
     [
         QUERY_ID,
         Feature("Group"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecHashJoinImpl",
     [
         QUERY_ID,
         Feature("HashJoin"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecIncrementalSort",
     [
         QUERY_ID,
         Feature("IncrementalSort"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecIndexOnlyScan",
     [
         QUERY_ID,
         Feature("IndexOnlyScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecIndexScan",
     [
         QUERY_ID,
         Feature("IndexScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecLimit",
     [
         QUERY_ID,
         Feature("Limit"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecLockRows",
     [
         QUERY_ID,
         Feature("LockRows"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecMaterial",
     [
         QUERY_ID,
         Feature("Material"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecMergeAppend",
     [
         QUERY_ID,
         Feature("MergeAppend"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecMergeJoin",
     [
         QUERY_ID,
         Feature("MergeJoin"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecModifyTable",
     [
         QUERY_ID,
         Feature("ModifyTable"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecNamedTuplestoreScan",
     [
         QUERY_ID,
         Feature("NamedTuplestoreScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecNestLoop",
     [
         QUERY_ID,
         Feature("NestLoop"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecProjectSet",
     [
         QUERY_ID,
         Feature("ProjectSet"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecRecursiveUnion",
     [
         QUERY_ID,
         Feature("RecursiveUnion"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecResult",
     [
         QUERY_ID,
         Feature("Result"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecSampleScan",
     [
         QUERY_ID,
         Feature("SampleScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecSeqScan",
     [
         QUERY_ID,
         Feature("Scan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecSetOp",
     [
         QUERY_ID,
         Feature("SetOp"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecSort",
     [
         QUERY_ID,
         Feature("Sort"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecSubPlan",
     [
         QUERY_ID,
         Feature("Plan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecSubqueryScan",
     [
         QUERY_ID,
         Feature("SubqueryScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecTableFuncScan",
     [
         QUERY_ID,
         Feature("TableFuncScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecTidScan",
     [
         QUERY_ID,
         Feature("TidScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecUnique",
     [
         QUERY_ID,
         Feature("Unique"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecValuesScan",
     [
         QUERY_ID,
         Feature("ValuesScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecWindowAgg",
     [
         QUERY_ID,
         Feature("WindowAgg"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
    ("ExecWorkTableScan",
     [
         QUERY_ID,
         Feature("WorkTableScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID
     ]),
]

# The metrics to be defined for every OU.
OU_METRICS = (
    BPFVariable(name="start_time",
                c_type=clang.cindex.TypeKind.ULONG,
                alignment=8),
    BPFVariable(name="end_time",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="cpu_cycles",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="instructions",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="cache_references",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="cache_misses",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="ref_cpu_cycles",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="network_bytes_read",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="network_bytes_written",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="disk_bytes_read",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="disk_bytes_written",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="memory_bytes",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="elapsed_us",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(name="pid",
                c_type=clang.cindex.TypeKind.UINT),
    BPFVariable(name="cpu_id",
                c_type=clang.cindex.TypeKind.UCHAR),
)


@dataclass
class OperatingUnit:
    """
    An operating unit is the NoisePage representation of a PostgreSQL operator.

    Parameters
    ----------
    function : str
        The name of the PostgreSQL function emitting the features.
    features_list : List[Feature]
        A list of features.
    """
    function: str
    features_list: List[Feature]

    def name(self) -> str:
        return self.function

    def begin_marker(self) -> str:
        return self.name() + '_begin'

    def end_marker(self) -> str:
        return self.name() + '_end'

    def features_marker(self) -> str:
        return self.name() + '_features'

    def flush_marker(self) -> str:
        return self.name() + '_flush'

    def features_struct(self) -> str:
        """
        Returns
        -------
        C struct definition of all the features in the OU.
        """

        struct_def = ''

        for feature in self.features_list:
            if feature.readarg_p:
                # This Feature is actually a struct struct that readarg_p will memcpy from user-space.
                assert (len(feature.bpf_tuple) >= 1), 'We should have some fields in this struct.'
                # Add all the struct's fields, sticking the original struct's alignment value on the first attribute.
                for column in feature.bpf_tuple:
                    struct_def = struct_def + (
                        '{} {}{};\n'.format(CLANG_TO_BPF[column.c_type], column.name, column.alignment_string()))
            else:
                # It's a single stack-allocated argument that we can read directly.
                assert (len(feature.bpf_tuple) == 1), 'How can something not using readarg_p have multiple fields?'
                struct_def = struct_def + (
                    '{} {};\n'.format(CLANG_TO_BPF[feature.bpf_tuple[0].c_type], feature.bpf_tuple[0].name))

        return struct_def

    def features_columns(self) -> str:
        """
        Returns
        -------
        Comma-separated string of all the features this OU outputs.
        This may not be all the features that comprise the OU.
        """
        return ','.join(
            column.name
            for feature in self.features_list
            for column in feature.bpf_tuple
            if column.should_output()
        )

    def serialize_features(self, output_event) -> str:
        """
        Serialize the feature values for this OU.

        Parameters
        ----------
        output_event
            The output event that contains feature values for all the
            features that this OU contains.

        Returns
        -------
        Comma-separated string of all the features this OU outputs.
        This may not be all the features that comprise the OU.
        """
        return ','.join(
            column.serialize(output_event)
            for feature in self.features_list
            for column in feature.bpf_tuple
            if column.should_output()
        )

    def helper_structs(self) -> Mapping[str, str]:
        decls = {}
        for feature in self.features_list:
            if feature.readarg_p:
                decl = [f'struct DECL_{feature.name}', '{']
                for column in feature.bpf_tuple:
                    decl.append(f'{CLANG_TO_BPF[column.c_type]} {column.name}{column.alignment_string()};')
                decl.append('};')
                decls[feature.name] = '\n'.join(decl)
        return decls


class Model:
    """


    TODO(WAN): Come up with a better name for this class.
    """

    def __init__(self):
        nodes = clang_parser.ClangParser()
        operating_units = []
        for postgres_function, features in OU_DEFS:
            feature_list = []
            for feature in features:
                # If an explicit list of BPF fields were specified,
                # our work is done. Continue on.
                if feature.bpf_tuple is not None:
                    assert feature.readarg_p is not None
                    feature_list.append(feature)
                    continue
                # Otherwise, convert the list of fields to BPF types.
                bpf_fields: List[BPFVariable] = []
                for i, field in enumerate(nodes.field_map[feature.name]):
                    try:
                        bpf_fields.append(
                            BPFVariable(
                                name=field.name,
                                c_type=field.canonical_type_kind,
                                alignment=field.alignment if i == 0 else None
                            )
                        )
                    except KeyError as e:
                        logger.critical(
                            'No mapping from Clang to BPF for type {} for field {} in the struct {}.'.format(e,
                                                                                                             field.name,
                                                                                                             feature.name))
                        exit()
                new_feature = Feature(feature.name,
                                      bpf_tuple=bpf_fields,
                                      readarg_p=True)
                feature_list.append(new_feature)

            new_ou = OperatingUnit(postgres_function, feature_list)
            operating_units.append(new_ou)

        self.operating_units = operating_units
        self.metrics = OU_METRICS
