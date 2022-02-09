from pathlib import Path

from doit import get_var

from dodos import VERBOSITY_DEFAULT


def task_ci_clean_slate():
    """
    CI: Clear out all artifacts and build folders.
    """
    folders = ["build"]

    return {
        "actions": [
            "rm -rf ./config.log ./config.status",
            *[f"sudo rm -rf {folder}" for folder in folders],
        ],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }


def task_ci_c():
    """
    CI: Format C code.
    """
    # Note that we do not want to format all of PostgreSQL.
    clang_files = [
        *Path("./cmudb/").rglob("*.[h,c]"),
        *Path("./src/backend/tscout/").rglob("*.[h,c]"),
        *Path("./src/include/tscout/").rglob("*.[h,c]"),
    ]
    clang_files_str = " ".join(str(path.absolute()) for path in clang_files)

    config = {"check": "--dry-run -Werror" if str(get_var("check")).lower() == "true" else "-i"}

    return {
        "actions": [
            f"clang-format -style=file {config['check']} {clang_files_str}",
        ],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }


def task_ci_python():
    """
    CI: Format and lint Python code.
    """
    folders = ["cmudb", "dodos"]
    config = {"check": "--check" if str(get_var("check")).lower() == "true" else ""}

    return {
        "actions": [
            *[f"black {config['check']} --verbose {folder}" for folder in folders],
            *[f"isort {config['check']} {folder}" for folder in folders],
            *[f"flake8 --statistics {folder}" for folder in folders],
            *[f"pylint --verbose {folder}" for folder in folders],
        ],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }
