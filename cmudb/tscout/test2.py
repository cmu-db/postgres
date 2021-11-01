import clang.cindex
import typing
from enum import Enum, unique
from typing import Tuple
from dataclasses import dataclass


@unique
class BPFType(str, Enum):
    i8 = "i8"
    i16 = "i16"
    i32 = "i32"
    i64 = "i64"
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


type_kind_to_bpf_type = {
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
    clang.cindex.TypeKind.POINTER: BPFType.u64
}


@dataclass
class Feature:
    name: str
    type: str
    canonical_type_kind: clang.cindex.TypeKind

    def is_simple(self):
        return (self.canonical_type_kind != clang.cindex.TypeKind.POINTER) and (
                self.canonical_type_kind != clang.cindex.TypeKind.RECORD)


index = clang.cindex.Index.create()
translation_unit = index.parse('/tmp/tmp.WznrhmOAMt/src/include/nodes/execnodes.h',
                               args=['-std=c17',
                                     '-I/tmp/tmp.WznrhmOAMt/src/include',
                                     '-I/usr/lib/gcc/x86_64-linux-gnu/9/include',
                                     '-I/usr/local/include',
                                     '-I/usr/include/x86_64-linux-gnu',
                                     '-I/usr/include'])


# print(list(translation_unit.diagnostics))


def filter_node_list_by_file(
        nodes: typing.Iterable[clang.cindex.Cursor],
        file_name: str
) -> typing.Iterable[clang.cindex.Cursor]:
    result = []

    for i in nodes:
        result.append(i)
        # if i.location.file.name == file_name:
        #     result.append(i)

    return result


def filter_node_list_by_node_kind(
        nodes: typing.Iterable[clang.cindex.Cursor],
        kinds: list
) -> typing.Iterable[clang.cindex.Cursor]:
    result = []

    for i in nodes:
        if i.kind in kinds:
            result.append(i)

    return result


def is_exposed_field(node):
    return node.access_specifier == clang.cindex.AccessSpecifier.PUBLIC


def find_all_exposed_fields(
        cursor: clang.cindex.Cursor
):
    result = []

    field_declarations = filter_node_list_by_node_kind(cursor.get_children(), [clang.cindex.CursorKind.FIELD_DECL])

    for i in field_declarations:
        feature = Feature(i.displayname, i.type.spelling, i.type.get_canonical().kind)
        result.append(feature)

    return result


source_nodes = filter_node_list_by_file(translation_unit.cursor.get_children(), translation_unit.spelling)
all_classes = filter_node_list_by_node_kind(source_nodes,
                                            [clang.cindex.CursorKind.CLASS_DECL, clang.cindex.CursorKind.STRUCT_DECL])

class_inheritance_map = {}
class_field_map = {}

for i in all_classes:
    bases = []

    for node in i.get_children():
        if node.kind == clang.cindex.CursorKind.CXX_BASE_SPECIFIER:
            referenceNode = node.referenced

            bases.append(node.referenced)

    class_inheritance_map[i.spelling] = bases

for i in all_classes:
    fields = find_all_exposed_fields(i)

    class_field_map[i.spelling] = fields


def populate_field_list_recursively(class_name: str):
    field_list = class_field_map.get(class_name)

    if field_list is None:
        return []

    baseClasses = class_inheritance_map[class_name]

    for i in baseClasses:
        field_list = populate_field_list_recursively(i.spelling) + field_list

    return field_list


rtti_map = {}

for class_name, class_list in class_inheritance_map.items():
    rtti_map[class_name] = populate_field_list_recursively(class_name)


def unroll_struct(class_name):
    fields = rtti_map[class_name]
    new_fields = []
    for f in fields:
        if f.canonical_type_kind == clang.cindex.TypeKind.RECORD:
            if f.type in rtti_map:
                new_fields.extend(unroll_struct(f.type))
            else:
                print('no type info for {} used in struct {}'.format(f.type, class_name))
        else:
            new_fields.append(f)
    return new_fields


def print_struct(class_name, field_list):
    wrapper_template = """\
{}:
{{
{}
}}

    """

    rendered_fields = []

    for f in field_list:
        rendered_fields.append(
            "\t{}, {}, {}".format(f.name, f.type, f.canonical_type_kind))

    print(wrapper_template.format(class_name, ",\n".join(rendered_fields)))


class_name = 'HashJoinState'

print_struct(class_name, rtti_map[class_name])
thing = unroll_struct(class_name)
print_struct(class_name, thing)


def prune_pointers(fields):
    features = []
    for f in fields:
        if f.canonical_type_kind != clang.cindex.TypeKind.POINTER:
            features.append(f)
    return features


thing2 = prune_pointers(thing)


def fields_to_features(fields):
    features = []
    for f in fields:
        features.append(BPFVariable(type_kind_to_bpf_type[f.canonical_type_kind], f.name))
    return features


features = fields_to_features(thing)

ou = OperatingUnit('test', 'test', tuple(features))

print(ou.features_struct() + '\n')

features = fields_to_features(thing2)

ou = OperatingUnit('test', 'test', tuple(features))

print(ou.features_struct())

# for class_name, field_list in rtti_map.items():
#     print_struct(class_name, field_list)
