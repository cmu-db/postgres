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

logger = logging.getLogger("tscout")

FLOAT_DOUBLE_NDIGITS = 3


@unique
class BPFType(str, Enum):
    """BPF only has signed and unsigned integers."""

    I8 = "s8"
    I16 = "s16"
    I32 = "s32"
    I64 = "s64"
    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    U64 = "u64"
    POINTER = "void *"


@dataclass
class BPFVariable:
    name: str
    c_type: clang.cindex.TypeKind
    alignment: int = None  # Non-None for the first field of a struct, using alignment value of the struct.

    def alignment_string(self):
        return f" __attribute__ ((aligned ({self.alignment})))" if self.alignment is not None else ""

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
            float_val = struct.unpack("f", getattr(output_event, self.name).to_bytes(4, byteorder=sys.byteorder))[0]
            float_val = round(float_val, FLOAT_DOUBLE_NDIGITS)
            return str(float_val)
        if self.c_type == clang.cindex.TypeKind.DOUBLE:
            double_val = struct.unpack("d", getattr(output_event, self.name).to_bytes(8, byteorder=sys.byteorder))[0]
            double_val = round(double_val, FLOAT_DOUBLE_NDIGITS)
            return str(double_val)

        return str(getattr(output_event, self.name))


# Map from Clang type kinds to BPF types.
CLANG_TO_BPF = {
    clang.cindex.TypeKind.BOOL: BPFType.U8,
    clang.cindex.TypeKind.CHAR_U: BPFType.U8,
    clang.cindex.TypeKind.UCHAR: BPFType.U8,
    clang.cindex.TypeKind.USHORT: BPFType.U16,
    clang.cindex.TypeKind.UINT: BPFType.U32,
    clang.cindex.TypeKind.ULONG: BPFType.U64,
    clang.cindex.TypeKind.ULONGLONG: BPFType.U64,
    clang.cindex.TypeKind.CHAR_S: BPFType.I8,
    clang.cindex.TypeKind.SCHAR: BPFType.I8,
    clang.cindex.TypeKind.SHORT: BPFType.I16,
    clang.cindex.TypeKind.INT: BPFType.I32,
    clang.cindex.TypeKind.LONG: BPFType.I64,
    clang.cindex.TypeKind.LONGLONG: BPFType.I64,
    clang.cindex.TypeKind.FLOAT: BPFType.U32,
    clang.cindex.TypeKind.DOUBLE: BPFType.U64,
    clang.cindex.TypeKind.ENUM: BPFType.I32,
    clang.cindex.TypeKind.POINTER: BPFType.POINTER,
    clang.cindex.TypeKind.FUNCTIONPROTO: BPFType.POINTER,
    clang.cindex.TypeKind.INCOMPLETEARRAY: BPFType.POINTER,
    clang.cindex.TypeKind.CONSTANTARRAY: BPFType.POINTER,
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


# The following mass definitions look messy after auto-formatting.
# fmt: off

# Internally, Postgres stores query_id as uint64. However, EXPLAIN VERBOSE and pg_stat_statements both represent
# query_id as BIGINT so TScout stores it as int64 to match this representation.
QUERY_ID = Feature("QueryId", readarg_p=False, bpf_tuple=(BPFVariable("query_id", clang.cindex.TypeKind.LONG),))
LEFT_CHILD_NODE_ID = Feature("left_child_plan_node_id", readarg_p=False,
                             bpf_tuple=(BPFVariable("left_child_plan_node_id", clang.cindex.TypeKind.INT),))
RIGHT_CHILD_NODE_ID = Feature("right_child_plan_node_id", readarg_p=False,
                              bpf_tuple=(BPFVariable("right_child_plan_node_id", clang.cindex.TypeKind.INT),))
STATEMENT_TIMESTAMP = Feature("statement_timestamp", readarg_p=False,
                              bpf_tuple=(BPFVariable("statement_timestamp", clang.cindex.TypeKind.LONG),))

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
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecAppend",
     [
         QUERY_ID,
         Feature("Append"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecBitmapAnd",
     [
         QUERY_ID,
         Feature("BitmapAnd"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecBitmapHeapScan",
     [
         QUERY_ID,
         Feature("BitmapHeapScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecBitmapIndexScan",
     [
         QUERY_ID,
         Feature("BitmapIndexScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecBitmapOr",
     [
         QUERY_ID,
         Feature("BitmapOr"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecCteScan",
     [
         QUERY_ID,
         Feature("CteScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecCustomScan",
     [
         QUERY_ID,
         Feature("CustomScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecForeignScan",
     [
         QUERY_ID,
         Feature("ForeignScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecFunctionScan",
     [
         QUERY_ID,
         Feature("FunctionScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecGather",
     [
         QUERY_ID,
         Feature("Gather"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecGatherMerge",
     [
         QUERY_ID,
         Feature("GatherMerge"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecGroup",
     [
         QUERY_ID,
         Feature("Group"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecHash",
     [
         QUERY_ID,
         Feature("Hash"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecHashJoinImpl",
     [
         QUERY_ID,
         Feature("HashJoin"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecIncrementalSort",
     [
         QUERY_ID,
         Feature("IncrementalSort"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecIndexOnlyScan",
     [
         QUERY_ID,
         Feature("IndexOnlyScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecIndexScan",
     [
         QUERY_ID,
         Feature("IndexScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecLimit",
     [
         QUERY_ID,
         Feature("Limit"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecLockRows",
     [
         QUERY_ID,
         Feature("LockRows"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecMaterial",
     [
         QUERY_ID,
         Feature("Material"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecMemoize",
     [
         QUERY_ID,
         Feature("Memoize"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecMergeAppend",
     [
         QUERY_ID,
         Feature("MergeAppend"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecMergeJoin",
     [
         QUERY_ID,
         Feature("MergeJoin"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecModifyTable",
     [
         QUERY_ID,
         Feature("ModifyTable"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecNamedTuplestoreScan",
     [
         QUERY_ID,
         Feature("NamedTuplestoreScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecNestLoop",
     [
         QUERY_ID,
         Feature("NestLoop"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecProjectSet",
     [
         QUERY_ID,
         Feature("ProjectSet"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecRecursiveUnion",
     [
         QUERY_ID,
         Feature("RecursiveUnion"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecResult",
     [
         QUERY_ID,
         Feature("Result"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecSampleScan",
     [
         QUERY_ID,
         Feature("SampleScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecSeqScan",
     [
         QUERY_ID,
         Feature("Scan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecSetOp",
     [
         QUERY_ID,
         Feature("SetOp"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecSort",
     [
         QUERY_ID,
         Feature("Sort"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecSubPlan",
     [
         QUERY_ID,
         Feature("Plan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecSubqueryScan",
     [
         QUERY_ID,
         Feature("SubqueryScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecTableFuncScan",
     [
         QUERY_ID,
         Feature("TableFuncScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecTidRangeScan",
     [
         QUERY_ID,
         Feature("TidRangeScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecTidScan",
     [
         QUERY_ID,
         Feature("TidScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecUnique",
     [
         QUERY_ID,
         Feature("Unique"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecValuesScan",
     [
         QUERY_ID,
         Feature("ValuesScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecWindowAgg",
     [
         QUERY_ID,
         Feature("WindowAgg"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
    ("ExecWorkTableScan",
     [
         QUERY_ID,
         Feature("WorkTableScan"),
         LEFT_CHILD_NODE_ID,
         RIGHT_CHILD_NODE_ID,
         STATEMENT_TIMESTAMP
     ]),
]

# The metrics to be defined for every OU. If you add anything to these metrics, consider if it should be accumulated
# across invocations and adjust code related to SUBST_ACCUMULATE as needed.
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

# fmt: on


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
        return self.name() + "_begin"

    def end_marker(self) -> str:
        return self.name() + "_end"

    def features_marker(self) -> str:
        return self.name() + "_features"

    def flush_marker(self) -> str:
        return self.name() + "_flush"

    def features_struct(self) -> str:
        """
        Returns
        -------
        C struct definition of all the features in the OU.
        """

        struct_def = ""

        for feature in self.features_list:
            if feature.readarg_p:
                # This Feature is actually a struct struct that readarg_p will memcpy from user-space.
                assert len(feature.bpf_tuple) >= 1, "We should have some fields in this struct."
                # Add all the struct's fields, sticking the original struct's alignment value on the first attribute.
                for column in feature.bpf_tuple:
                    struct_def = struct_def + (
                        f"{CLANG_TO_BPF[column.c_type]} {column.name}{column.alignment_string()};\n"
                    )
            else:
                # It's a single stack-allocated argument that we can read directly.
                assert len(feature.bpf_tuple) == 1, "How can something not using readarg_p have multiple fields?"
                struct_def = struct_def + (
                    f"{CLANG_TO_BPF[feature.bpf_tuple[0].c_type]} {feature.bpf_tuple[0].name};\n"
                )

        return struct_def

    def features_columns(self) -> str:
        """
        Returns
        -------
        Comma-separated string of all the features this OU outputs.
        This may not be all the features that comprise the OU.
        """
        return ",".join(
            column.name for feature in self.features_list for column in feature.bpf_tuple if column.should_output()
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
        return ",".join(
            column.serialize(output_event)
            for feature in self.features_list
            for column in feature.bpf_tuple
            if column.should_output()
        )

    def helper_structs(self) -> Mapping[str, str]:
        decls = {}
        for feature in self.features_list:
            if feature.readarg_p:
                decl = [f"struct DECL_{feature.name}", "{"]
                for column in feature.bpf_tuple:
                    decl.append(f"{CLANG_TO_BPF[column.c_type]} {column.name}{column.alignment_string()};")
                decl.append("};")
                decls[feature.name] = "\n".join(decl)
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
                                alignment=field.alignment if i == 0 else None,
                            )
                        )
                    except KeyError as e:
                        logger.critical(
                            "No mapping from Clang to BPF for type %s for field %s in the struct %s.",
                            e,
                            field.name,
                            feature.name,
                        )
                        sys.exit(1)
                new_feature = Feature(feature.name, bpf_tuple=bpf_fields, readarg_p=True)
                feature_list.append(new_feature)

            new_ou = OperatingUnit(postgres_function, feature_list)
            operating_units.append(new_ou)

        self.operating_units = operating_units
        self.metrics = OU_METRICS
        self._enums = nodes.enum_map

    def get_enum_value_map(self, enum_name):
        """
        Construct and return a mapping between the enumeration constants
        and the corresponding values of the constants.

        Parameters
        ----------
        enum_name
            The name of the enumeration.
            The enumerations are parsed from the PostgreSQL source code by
            the Clang Parser at the time of initializing the model class.


        Returns
        -------
        A map whose keys are the enumeration constants and values are the
        the corresponding values of the constants.
        """
        assert enum_name in self._enums.keys(), f"Requested enum {enum_name} not in PostgreSQL code base."

        return {entry[0]: entry[1] for entry in self._enums[enum_name]}
