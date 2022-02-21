import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Tuple

from clang.cindex import TypeKind
from tscout import model

# We're assuming that this script is housed in `postgres/cmudb/extensions/tscout`.
# We calculate the path of TScout relative to this extension and add it to the PythonPath temporarily.
TSCOUT_EXTENSION_PATH = Path(__file__).parent
CODEGEN_TEMPLATE_PATH = Path.joinpath(TSCOUT_EXTENSION_PATH, "operating_unit_codegen.c")
CODEGEN_FILE_PATH = Path.joinpath(TSCOUT_EXTENSION_PATH, "operating_unit_features.h")


@dataclass
class ExtractionOU:
    """
    Represents an Operating Unit whose features are to be extracted from a running instance of PostgreSQL.

    ou_index : int
        The index of the Operating Unit (OU) in the list of OUs produced by the Model class.
    pg_enum_index : int
        The index/value of the corresponding enumeration constant in the PostgreSQL source code.
    ou_name: str
        The name of the Operating Unit.
    features: List[Tuple[str, TypeKind]]
        The list of (feature-name, feature-data-type) pairs which correspond to the features.
    """

    ou_index: int
    pg_enum_index: int
    ou_name: str
    features: List[Tuple[str, TypeKind]]


OU_TO_FEATURE_LIST_MAP: Mapping[int, ExtractionOU] = {}

# The following OUs do not follow the general naming convention:
# OU Name: ExecABC
# Postgres struct name: T_ABC
# We capture these OUs as exceptions manually.
# TODO (Karthik): Find out when and why this happens.
OU_EXCEPTIONS = {"ExecHashJoinImpl": "T_HashJoin"}
OU_EXCLUDED_FEATURES = [
    "query_id",
    "left_child_plan_node_id",
    "right_child_plan_node_id",
    "statement_timestamp",
]


def aggregate_features(ou):
    """
    Extract the name and type of every feature for the given OU.

    Parameters
    ----------
    ou : model.OperatingUnit
        The OU to extract features from.

    Returns
    -------
    features_list : List[Tuple[str, clang.cindex.TypeKind]]
        The [(name, type)] of all features for the given OU.
    """
    features_list = []
    for feature in ou.features_list:
        for variable in feature.bpf_tuple:
            if variable.pg_type == 'List *':
                # This is not a long-term solution if we start defining more encoded types.
                features_list.append((variable.name, variable.pg_type))
            elif variable.name in OU_EXCLUDED_FEATURES:
                continue
            else:
                features_list.append((variable.name, variable.c_type))

    return features_list


def add_features(features_string, feat_index, ou_xs):
    """
    Build up the features string for the given OU.

    Parameters
    ----------
    features_string : str
        The string containing all the features.
        Initialize with the empty string.
    feat_index : int
        The index of the feature to extract.
    ou_xs : List[Tuple[str, clang.cindex.TypeKind]]
        The (names, types) of all the features for the given OU.

    Returns
    -------
    new_features_string : str
        The new features string for the given OU.
    """
    features_string += "\n"
    features_struct_list = []
    for x in ou_xs:
        (name, value) = x
        type_kind = "T_UNKNOWN"
        if value == "List *":
            type_kind = "T_LIST_PTR"  # This is not a long-term solution if we start defining more encoded types.
        elif value == TypeKind.POINTER:
            type_kind = "T_PTR"
        elif value in [TypeKind.INT, TypeKind.UINT]:
            type_kind = "T_INT"
        elif value in [TypeKind.LONG, TypeKind.ULONG]:
            type_kind = "T_LONG"
        elif value == TypeKind.SHORT:
            type_kind = "T_SHORT"
        elif value == TypeKind.DOUBLE:
            type_kind = "T_DOUBLE"
        elif value == TypeKind.ENUM:
            type_kind = "T_ENUM"
        elif value == TypeKind.BOOL:
            type_kind = "T_BOOL"
        else:
            type_kind = str(value)
        features_struct_list.append(f'{{ {type_kind}, "{name}" }}')

    features_struct = str.join(", ", features_struct_list)
    features_string += f"field feat_{feat_index:d}[] = {{ " + features_struct + " };"

    return features_string


def fill_in_template(ou_string, ou_index, node_type, ou_xs):
    """
    Fill in the codegen template for the given OU.

    Parameters
    ----------
    ou_string : str
        The current ou_string.
    ou_index : int
        The index of the OU.
    node_type : str
        The name of the OU.
    ou_xs : List[Tuple[str, clang.cindex.TypeKind]]
        The (name, type) of all features for the OU.

    Returns
    -------
    new_ou_string : str
        The codegen template with the given OU's details substituted.
    """
    # Replace the index of the OU.
    ou_string = ou_string.replace("OU_INDEX", f"{ou_index:d}")
    # Replace the name of the OU.
    ou_string = ou_string.replace("OU_NAME", f'"{node_type}"')
    # Compute and replace the number of features.
    ou_string = ou_string.replace("NUM_Xs", f"{len(ou_xs):d}")

    # If there are features, add the list of features.
    # Otherwise, replace with a dummy string.
    if ou_xs:
        ou_string = ou_string.replace("OU_Xs", f"feat_{ou_index}")
    else:
        ou_string = ou_string.replace("OU_Xs", "feat_none")

    return ou_string


def main():
    """
    Generate the TScout features and fill in the codegen template.
    """
    modeler = model.Model()

    # Fetch the NodeTag enum.
    pg_mapping = modeler.get_enum_value_map("NodeTag")
    for i in range(len(pg_mapping)):
        OU_TO_FEATURE_LIST_MAP[i] = {}

    # Populate the NodeTag's details.
    for (index, ou) in enumerate(modeler.operating_units):
        if ou.name().startswith("Exec"):
            struct_name = ou.name()[len("Exec"):]
            pg_struct_name = "T_" + struct_name
            pg_enum_index = None

            if pg_struct_name in pg_mapping.keys():
                pg_enum_index = pg_mapping[pg_struct_name]
            elif ou.name() in OU_EXCEPTIONS:
                pg_struct_name = OU_EXCEPTIONS[ou.name()]
                pg_enum_index = pg_mapping[pg_struct_name]

            if pg_enum_index:
                OU_TO_FEATURE_LIST_MAP[pg_enum_index] = ExtractionOU(
                    index, pg_mapping[pg_struct_name], ou.name(), aggregate_features(ou)
                )

    # Open and analyse the codegen file.
    with open(str(CODEGEN_TEMPLATE_PATH), "r", encoding="utf-8") as template:
        text = template.read()

        # Find a sequence that matches "(ou){.*},".
        matches = re.findall(r"\(ou\){.*},", text)
        assert len(matches) == 1

        feat_matcher = re.findall(r"// Features go here.", text)
        assert len(matches) == 1

        match = matches[0]
        feat_match = feat_matcher[0]

        ou_struct_list = []
        features_list_string = ""
        # For each OU, generate the features and fill in the codegen template.
        for (key, value) in OU_TO_FEATURE_LIST_MAP.items():
            # Initialize with the matching string.
            ou_string = match
            if value:
                ou_xs = value.features
                ou_string = fill_in_template(ou_string, key, value.ou_name, ou_xs)
                features_list_string = add_features(features_list_string, key, ou_xs)
            else:
                # Print defaults.
                ou_string = fill_in_template(ou_string, -1, "", [])

            ou_struct_list.append(ou_string)

        ou_struct_list_string = str.join("\n", ou_struct_list)

        text = text.replace(match, ou_struct_list_string)
        text = text.replace(feat_match, features_list_string)
        with open(CODEGEN_FILE_PATH, "w", encoding="utf-8") as gen_file:
            gen_file.write(text)


if __name__ == "__main__":
    main()
