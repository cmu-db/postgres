"""
clang_parser.py

Parse C code into a map which maps from (struct name) to
(base-class- and record-type- expanded fields list).
"""

from dataclasses import dataclass
from typing import List, Mapping

import clang.cindex

# Expected path of this file: "postgres/cmudb/tscout/"

# Path to the Postgres root.
CLANG_POSTGRES_PATH = r'../../../postgres'
# Path to the execnodes.h file.
CLANG_EXECNODES_H = f'{CLANG_POSTGRES_PATH}/src/include/nodes/execnodes.h'
# The arguments that Clang uses to parse header files.
CLANG_ARGS = [
    '-std=c17',
    f'-I{CLANG_POSTGRES_PATH}/src/include',
    '-I/usr/lib/gcc/x86_64-linux-gnu/9/include',
    '-I/usr/local/include',
    '-I/usr/include/x86_64-linux-gnu',
    '-I/usr/include',
]


@dataclass
class Field:
    """A field of a struct, as parsed by Clang."""
    name: str
    pg_type: str
    canonical_type_kind: clang.cindex.TypeKind


class ClangParser:
    """
    On init, ClangParser parses the PostgreSQL source code to construct a
    mapping from struct name to a list of the struct fields, where the fields
    list has both base classes expanded and record types expanded.

    Attributes
    ----------
    field_map : Mapping[str, List[Field]]
        Maps from (struct name) to a (base-class- and record-type-
        expanded list of all fields for the struct).
    """

    def __init__(self):
        # Parse the translation unit.
        index = clang.cindex.Index.create()
        translation_unit = index.parse(CLANG_EXECNODES_H, args=CLANG_ARGS)

        # To construct the field map, we will construct the following objects:
        # 1. _classes
        #       Extract a list of all classes in the translation unit.
        # 2. _bases
        #       Extract a mapping from class name to all base classes.
        # 3. _fields
        #       Extract a mapping from class name to all the fields,
        #       but base classes not expanded, record types not expanded.
        # 4. _rtti_map
        #       _fields with base classes expanded.
        # 5. field_map
        #       _fields with base classes expanded and record types expanded.

        # _classes : list of all classes in the translation unit
        self._classes: List[clang.cindex.Cursor] = [
            node
            for node in translation_unit.cursor.get_children()
            if node.kind in [clang.cindex.CursorKind.CLASS_DECL,
                             clang.cindex.CursorKind.STRUCT_DECL]
        ]
        self._classes = sorted(self._classes, key=lambda node: node.spelling)

        # _bases : class name -> list of base classes for the class
        self._bases: Mapping[str, List[clang.cindex.Cursor]] = {
            node.spelling: [
                child.referenced
                for child in node.get_children()
                if child.kind == clang.cindex.CursorKind.CXX_BASE_SPECIFIER
            ]
            for node in self._classes
        }

        # _fields : class name -> list of fields in the class
        self._fields: Mapping[str, List[Field]] = {
            node.spelling: [
                Field(
                    child.displayname,
                    child.type.spelling,
                    child.type.get_canonical().kind
                )
                for child in node.get_children()
                if child.kind == clang.cindex.CursorKind.FIELD_DECL
            ]
            for node in self._classes
        }

        # _rtti_map : class name ->
        #               list of fields in the class with base classes expanded
        self._rtti_map: Mapping[str, List[Field]] = {
            node_name: self._construct_base_expanded_fields(node_name)
            for node_name in self._bases
        }

        # field_map: class name ->
        #               list of fields in the class with base classes expanded
        #               and record types expanded
        self.field_map: Mapping[str, List[Field]] = {
            node_name:
                self._construct_fully_expanded_fields(
                    node_name,
                    prefix=f'{node_name}_'
                )
            for node_name in self._bases
        }

    def _construct_base_expanded_fields(self, class_name):
        """
        Construct the list of base-class-expanded fields.
        Depends on self._fields and self._bases.

        Base class fields are prepended.

        Parameters
        ----------
        class_name : str
            The name of the class to construct a field list for.

        Returns
        -------
        A base-class-expanded list of fields for the input class.
        """
        fields, bases = self._fields, self._bases

        # If the class has no fields, we are done.
        field_list = fields.get(class_name)
        if field_list is None:
            return []

        # Otherwise, if there are any base classes,
        # recursively prepend the fields from the base classes,
        # and then return the fields for this class.
        base_classes = bases[class_name]
        for base_class in base_classes:
            base = self._construct_base_expanded_fields(base_class.spelling)
            field_list = base + field_list
        return field_list

    def _construct_fully_expanded_fields(self, class_name, prefix=''):
        """
        Construct the list of base-class- and record-type- expanded fields.
        Depends on self._rtti_map.

        Parameters
        ----------
        class_name : str
            The name of the class to construct a field list for.

        prefix : str
            Recursive helper parameter, will be prefixed onto field names.

        Returns
        -------
        A base-class- and record-type- expanded list of fields for the class.

        Warnings
        --------
        Record types are only expanded wherever possible, and are otherwise
        dropped after printing a warning.
        """
        rtti_map = self._rtti_map

        fields = rtti_map[class_name]
        new_fields = []
        # For every field in the base-class-expanded field list for the class,
        for field in fields:
            if field.canonical_type_kind != clang.cindex.TypeKind.RECORD:
                # If the field is not a record type,
                # just append the field to the list of new fields.
                new_field = Field(f'{prefix}{field.name}',
                                  field.pg_type,
                                  field.canonical_type_kind)
                new_fields.append(new_field)
            else:
                # If the field is a record type, try adding the list of
                # base-class- and record-type- expanded fields.
                # However, this is not always possible,
                # e.g., for non-PostgreSQL structs.
                if field.pg_type not in rtti_map:
                    print(f"No type info for {field.pg_type} "
                          f"used in {class_name}.")
                else:
                    expanded_fields = self._construct_fully_expanded_fields(
                        field.pg_type,
                        prefix=prefix + f'{field.name}_')
                    new_fields.extend(expanded_fields)
        return new_fields
