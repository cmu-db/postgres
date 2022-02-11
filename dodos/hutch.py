import os

import doit

from dodos import VERBOSITY_DEFAULT


def task_hutch_install():
    """
    Hutch: Compile and install the Hutch extension.
    """
    return {
        "actions": [
            lambda: os.chdir("cmudb/extensions/hutch/"),
            # Generate the necessary features.
            "sudo PYTHONPATH=../../tscout:$PYTHONPATH python3 tscout_feature_gen.py",
            # Install the extension into the default build directory's PostgreSQL.
            # Note that the PG_CONFIG env var can be specified to override which
            # PostgreSQL the extension gets installed into.
            "PG_CONFIG=%(pg_config)s make clean -j",
            "PG_CONFIG=%(pg_config)s make -j",
            "PG_CONFIG=%(pg_config)s make install -j",
            # Reset working directory.
            lambda: os.chdir(doit.get_initial_workdir()),
        ],
        "verbosity": VERBOSITY_DEFAULT,
        "uptodate": [False],
        "params": [
            {
                "name": "pg_config",
                "long": "pg_config",
                "help": "The location of the pg_config binary.",
                "default": "../../../build/bin/pg_config",
            },
        ],
    }
