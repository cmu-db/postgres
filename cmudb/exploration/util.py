import signal
import subprocess
import sys
from enum import Enum
from typing import AnyStr, List, Tuple, Union

# Project (relative to exploration directory)
PROJECT_ROOT = "../.."
ENV_FOLDER = "../env"

# Docker
CONTAINER_BIN_DIR = "/home/terrier/repo/build/bin"
DOCKER_VOLUME_DIR = "/mnt/docker/volumes"
IMAGE_TAG = "pgnp"
EXPLORATION_CONTAINER_NAME = "exploration"
EXPLORATORY_COMPOSE = "docker-compose-exploration.yml"
EXPLORATORY_PROJECT_NAME = "exploratory"

# Postgres
REPLICA_PORT = 15722
EXPLORATION_PORT = 42666

# ZFS
ZFS_DOCKER_VOLUME_POOL = "zpool-docker/volumes"
REPLICA_VOLUME_POOL = "pgdata-replica"
EXPLORATION_VOLUME_POOL = "pgdata-exploration"
ZFS_SNAPSHOT_NAME = "explore"

# Misc
UTF_8 = "utf-8"


class OutputStrategy(Enum):
    CAPTURE = (subprocess.PIPE, subprocess.PIPE)
    PRINT = (sys.stdout, sys.stderr)
    HIDE = (subprocess.DEVNULL, subprocess.DEVNULL)


def execute_sys_command(
    cmd: Union[str, List[str]],
    block: bool = True,
    output_strategy: OutputStrategy = OutputStrategy.PRINT,
    cwd: str = None,
    env=None,
) -> Tuple[subprocess.Popen, AnyStr, AnyStr]:
    """
    Execute bash command
    Parameters
    ----------
    cmd
        command to execute
    block
        whether or not to block until command is complete
    output_strategy
        strategy for handling command output
    cwd
        Sets the current directory before the child is executed.
    env
        Defines the environment variables for the new process.
    Returns
    -------
    process
        process running command
    stdout
        stdout if block is True and output_strategy is Capture
    stderr
        stderr if block is True and output_strategy is Capture
    """
    if isinstance(cmd, str):
        cmd = cmd.split(" ")

    res = subprocess.Popen(  # pylint: disable=consider-using-with
        cmd, stdout=output_strategy.value[0], stderr=output_strategy.value[1], cwd=cwd, env=env
    )
    out = ""
    err = ""
    if block:
        out, err = res.communicate()
        out = out.decode(UTF_8) if out is not None else ""
        err = err.decode(UTF_8) if err is not None else ""

    return res, out, err


def stop_process(proc: subprocess.Popen):
    """
    Stop process
    Parameters
    ----------
    proc
        process to stop
    """
    proc.send_signal(signal.SIGTERM)
    try:
        proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.terminate()
