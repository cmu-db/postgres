import os
import subprocess
import time
from typing import List

from pgnp_docker import execute_in_container
from util import CONTAINER_BIN_DIR, OutputStrategy, execute_sys_command

# SQL functionality


def execute_sql(query: str, port: int) -> List[str]:
    """
    Execute SQL query
    Parameters
    ----------
    query
        SQL query to execute
    port
        port that postgres instance is running on
    Returns
    -------
    output
        output of SQL query
    """
    env = os.environ.copy()
    env["PGPASSWORD"] = "terrier"
    cmd = f"psql -h localhost -p {port} -U noisepage -t -P pager=off".split(" ")
    cmd.append(f"--command={query}")
    cmd.append("noisepage")
    # For sql_command, err. pylint: disable=unused-variable
    sql_command, out, err = execute_sys_command(cmd, env=env, output_strategy=OutputStrategy.CAPTURE)
    return [row.strip() for row in out.split("\n") if row.strip()]


def checkpoint(port: int) -> List[str]:
    """
    Run CHECKPOINT
    Parameters
    ----------
    port
        port that postgres instance is running on
    Returns
    -------
    output
        output of CHECKPOINT query
    """
    return execute_sql("CHECKPOINT", port)


# Postgres functionality


def is_pg_ready(container_name: str, port: int) -> bool:
    """
    Determine if postgres instance is ready
    Parameters
    ----------
    container_name
        name of docker container running postgres instance
    port
        port that postgres instance is running on
    Returns
    -------
    is_ready
        True if postgres is ready, False otherwise
    """
    is_ready_res, _, _ = execute_in_container(
        container_name,
        f"{CONTAINER_BIN_DIR}/pg_isready --host {container_name} --port {port} " f"--username noisepage",
        output_strategy=OutputStrategy.HIDE,
    )
    return is_ready_res.returncode == 0


# TODO add timeout
def wait_for_pg_ready(container_name: str, port: int, postgres_process: subprocess.Popen) -> bool:
    """
    Wait for postgres instance to be ready
    Parameters
    ----------
    container_name
        name of docker container running postgres instance
    port
        port that postgres instance is running on
    postgres_process
        process running postgres instance
    Returns
    -------
    is_ready
        True if postgres is ready, False if postgres failed to startup
    """
    while not is_pg_ready(container_name, port) and postgres_process.poll() is None:
        time.sleep(1)

    # Return code is only set when process exits and postgres proc shouldn't exit
    if postgres_process.returncode is not None:
        print(f"Postgres instance failed to start up with error code: {postgres_process.returncode}")
        return False

    return True
