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
POSTGRES_PATH = r'../..'
# Path to the Postgres files to parse.
POSTGRES_FILES = (
    f'{POSTGRES_PATH}/src/include/nodes/execnodes.h',
)
# The arguments that Clang uses to parse header files.
CLANG_ARGS = [
    '-std=c17',
    f'-I{POSTGRES_PATH}/src/include',
    '-I/usr/lib/gcc/x86_64-linux-gnu/9/include',
    '-I/usr/local/include',
    '-I/usr/include/x86_64-linux-gnu',
    '-I/usr/include',
]


def convert_define_to_arg(input_define):
    """
    Convert from a #define to a command line arg.

    Parameters
    ----------
    input_define : str
        String in the format of "#define variable value".

    Returns
    -------
    output_str : str
        String in the format of "-Dvariable=value".
    """
    var_and_value = input_define.rstrip()[len('#define '):]
    separator = var_and_value.find(' ')
    var = var_and_value[:separator]
    value = var_and_value[separator + 1:]
    return f'-D{var}={value}'


# Grab the results of ./configure to make sure that we're passing the same
# preprocessor #defines to libclang as when compiling Postgres.
# #defines can affect struct sizing depending on machine environment.
with open(f'{POSTGRES_PATH}/config.log') as config_file:
    for config_line in config_file:
        if config_line.startswith('#define '):
            CLANG_ARGS.append(convert_define_to_arg(config_line))


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
        indexes: List[clang.cindex.Index] = []
        translation_units: List[clang.cindex.TranslationUnit] = []
        classes: Mapping[str, clang.cindex.Cursor] = {}

        # Parse each postgres file's definitions into the classes map.
        # classes is a map to handle potential duplicate definitions
        # from parsing multiple translation units.
        for postgres_file in POSTGRES_FILES:
            # Parse the translation unit.
            index = clang.cindex.Index.create()
            tu = index.parse(postgres_file, args=CLANG_ARGS)

            # Keep the index and translation unit alive for the rest of init.
            indexes.append(index)
            translation_units.append(tu)

            # Add all relevant definitions to the classes map.
            for node in tu.cursor.get_children():
                kind_ok = node.kind in [
                    clang.cindex.CursorKind.CLASS_DECL,
                    clang.cindex.CursorKind.STRUCT_DECL,
                    # Fixes instr_time def in instr_time.h.
                    clang.cindex.CursorKind.TYPEDEF_DECL,
                    clang.cindex.CursorKind.UNION_DECL,
                ]

                is_new = node.spelling not in classes
                has_previous_typedef = not is_new and classes[
                    node.spelling].kind == clang.cindex.CursorKind.TYPEDEF_DECL
                override_previous_typedef = has_previous_typedef and node.kind != clang.cindex.CursorKind.TYPEDEF_DECL
                if override_previous_typedef:
                    print(node.spelling)
                # Fix forward declarations clobbering definitions.
                is_real_def = node.is_definition()

                if kind_ok and (is_new or override_previous_typedef) and is_real_def:
                    classes[node.spelling] = node

        # To construct the field map, we will construct the following objects:
        # 1. _classes
        #       Extract a list of all classes in the translation units.
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
        self._classes: List[clang.cindex.Cursor] = classes.values()
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
