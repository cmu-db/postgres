from pathlib import Path

from dodos import VERBOSITY_DEFAULT

ROOT_FOLDER = Path(__file__).parent.parent.absolute()
ARTIFACT_config_log = (ROOT_FOLDER / "config.log").absolute()
ARTIFACT_postgres = (ROOT_FOLDER / "build/bin/postgres").absolute()


def task_np_config_clear():
    """
    NoisePage: Clear the old config file. THIS MUST BE DONE FOR np_config TO SWITCH BUILD TYPES.
    """
    return {
        "actions": [
            "rm -rf ./config.log ./config.status",
        ],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }


def task_np_config():
    """
    NoisePage: Configure building in either debug or release mode.
    """
    return {
        "actions": [
            "./cmudb/build/configure.sh %(build_type)s",
        ],
        "targets": [ARTIFACT_config_log],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [True],
        "params": [
            {
                "name": "build_type",
                "long": "build_type",
                "help": 'Must be either "debug" or "release", defaults to "debug".',
                "default": "debug",
            },
        ],
    }


def task_np_clean():
    """
    NoisePage: Clean any previous NoisePage binary build.
    """
    return {
        "actions": [
            "make -j clean",
        ],
        "file_dep": [ARTIFACT_config_log],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }


def task_np_build():
    """
    NoisePage: Build the NoisePage binary.
    """
    return {
        "actions": [
            "make -j install-world-bin",
        ],
        "file_dep": [ARTIFACT_config_log],
        "targets": [ARTIFACT_postgres],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }


def task_np_test_core():
    """
    NoisePage: Run the core PostgreSQL tests.
    """
    return {
        "actions": [
            "make -j check",
        ],
        "file_dep": [ARTIFACT_postgres],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }


def task_np_test_all():
    """
    NoisePage: Run all the PostgreSQL tests.
    """
    return {
        "actions": [
            "make -j check-world",
        ],
        "file_dep": [ARTIFACT_postgres],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
    }
