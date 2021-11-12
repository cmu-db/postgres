"""
model.py

Convert C types to BPF types.
Define the Operating Units (OUs) and metrics to be collected.
"""

import struct
import sys
from dataclasses import dataclass
from enum import Enum, unique
from typing import List, Mapping, Tuple

import clang.cindex

import clang_parser


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


@dataclass
class BPFVariable:
    """A BPF variable has a type and a name."""
    bpf_type: BPFType
    name: str
    c_type: clang.cindex.TypeKind

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
        A tuple of all the BPF-typed variables that comprise this feature.
    """
    name: str
    readarg_p: bool = None
    bpf_tuple: Tuple[BPFVariable] = None


QUERY_ID = (BPFVariable(BPFType.u64, "query_id", clang.cindex.TypeKind.ULONG),)

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
    # ("ExecAgg",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("AggState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecAppend",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("AppendState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecCteScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("CteScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecCustomScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("CustomScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecForeignScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("ForeignScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecFunctionScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("FunctionScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecGather",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("GatherState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecGatherMerge",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("GatherMergeState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecGroup",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("GroupState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecHashJoinImpl",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("HashJoinState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecIncrementalSort",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("IncrementalSortState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecIndexOnlyScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("IndexOnlyScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecIndexScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("IndexScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecLimit",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("LimitState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecLockRows",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("LockRowsState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecMaterial",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("MaterialState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecMergeAppend",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("MergeAppendState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecMergeJoin",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("MergeJoinState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecModifyTable",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("ModifyTableState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecNamedTuplestoreScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("NamedTuplestoreScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecNestLoop",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("NestLoopState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecProjectSet",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("ProjectSetState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecRecursiveUnion",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("RecursiveUnionState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecResult",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("ResultState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecSampleScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("SampleScanState"),
    #      Feature("Plan")
    #  ]),
    ("ExecSeqScan",
     [
         Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
         Feature("SeqScanState"),
         Feature("Plan")
     ]),
    # ("ExecSetOp",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("SetOpState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecSort",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("SortState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecSubPlan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("SubPlan"),
    #      Feature("Plan")
    #  ]),
    # ("ExecSubqueryScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("SubqueryScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecTableFuncScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("TableFuncScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecTidScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("TidScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecUnique",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("UniqueState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecValuesScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("ValuesScanState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecWindowAgg",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("WindowAggState"),
    #      Feature("Plan")
    #  ]),
    # ("ExecWorkTableScan",
    #  [
    #      Feature("QueryId", readarg_p=False, bpf_tuple=QUERY_ID),
    #      Feature("WorkTableScanState"),
    #      Feature("Plan")
    #  ]),
]

# The metrics to be defined for every OU.
OU_METRICS = (
    BPFVariable(bpf_type=BPFType.u64,
                name="start_time",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="end_time",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u8,
                name="cpu_id",
                c_type=clang.cindex.TypeKind.UCHAR),
    BPFVariable(bpf_type=BPFType.u64,
                name="cpu_cycles",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="instructions",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="cache_references",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="cache_misses",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="ref_cpu_cycles",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="network_bytes_read",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="network_bytes_written",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="disk_bytes_read",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="disk_bytes_written",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="memory_bytes",
                c_type=clang.cindex.TypeKind.ULONG),
    BPFVariable(bpf_type=BPFType.u64,
                name="elapsed_us",
                c_type=clang.cindex.TypeKind.ULONG)
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

    def features_struct(self) -> str:
        """
        Returns
        -------
        C struct definition of all the features in the OU.
        """
        struct_def = ';\n'.join(
            '{} {}'.format(column.bpf_type, column.name)
            for feature in self.features_list
            for column in feature.bpf_tuple
        )
        return struct_def + ';'

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
                    decl.append(f'{column.bpf_type} {column.name};')
                decl.append('};')
                decls[feature.name] = '\n'.join(decl)
        return decls


class Model:
    """


    TODO(WAN): Come up with a better name for this class.
    """

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
        clang.cindex.TypeKind.POINTER: BPFType.u64,
        clang.cindex.TypeKind.FUNCTIONPROTO: BPFType.u64,
    }

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
                bpf_fields = tuple([
                    BPFVariable(
                        bpf_type=Model.CLANG_TO_BPF[field.canonical_type_kind],
                        name=field.name,
                        c_type=field.canonical_type_kind,
                    )
                    for i, field in enumerate(nodes.field_map[feature.name])
                ])

                new_feature = Feature(feature.name,
                                      bpf_tuple=bpf_fields,
                                      readarg_p=True)
                feature_list.append(new_feature)

            new_ou = OperatingUnit(postgres_function, feature_list)
            operating_units.append(new_ou)

        self.operating_units = operating_units
        self.metrics = OU_METRICS
