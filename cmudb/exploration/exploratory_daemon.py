import argparse
import subprocess
from typing import Tuple

from data_copy import copy_pgdata_cow, destroy_exploratory_data_cow
from pgnp_docker import (
    setup_docker_env,
    shutdown_exploratory_docker,
    start_exploration_docker,
)
from sql import checkpoint, execute_sql, wait_for_pg_ready
from util import (
    DOCKER_VOLUME_DIR,
    EXPLORATION_CONTAINER_NAME,
    EXPLORATION_PORT,
    REPLICA_PORT,
    REPLICA_VOLUME_POOL,
    ZFS_DOCKER_VOLUME_POOL,
    execute_sys_command,
)


def main():
    """
    The exploratory daemon is responsible for creating a copy of replica instances, to be used for model training.
    To set up a machine to ues the exploratory daemon you must perform the following steps:
    1. Install ZFS on one of the disks
    2. Set up a ZFS pool on the disk
    3. Start a postgres instance that stores pgdata/ in the ZFS pool
    """
    aparser = argparse.ArgumentParser(description="Exploratory Daemon")
    # postgres args
    aparser.add_argument(
        "--postgres-replica-port", help="Port that replica instance is running on", default=REPLICA_PORT
    )
    aparser.add_argument(
        "--postgres-exploratory-port", help="Port that exploratory instance will run on", default=EXPLORATION_PORT
    )
    # ZFS args
    aparser.add_argument(
        "--zfs-volume-pool", help="ZFS pool name for docker volume directory", default=ZFS_DOCKER_VOLUME_POOL
    )
    aparser.add_argument(
        "--zfs-replica-pool-name",
        help="Relative name of ZFS pool used for the replica volume",
        default=REPLICA_VOLUME_POOL,
    )
    # Docker args
    aparser.add_argument(
        "--docker-volume-directory", help="directory path of the docker volume directory", default=DOCKER_VOLUME_DIR
    )
    args = vars(aparser.parse_args())

    run_daemon(
        args["postgres_replica_port"],
        args["postgres_exploratory_port"],
        args["zfs_volume_pool"],
        args["zfs_replica_pool_name"],
        args["docker_volume_directory"],
    )


def run_daemon(
    replica_port: int, exploratory_port: int, zfs_volume_pool: str, zfs_replica_pool: str, docker_volume_dir: str
):
    """
    Run exploratory daemon
    Parameters
    ----------
    replica_port
        port that replica instance is reachable from
    exploratory_port
        port that exploratory instance will be reachable from
    zfs_volume_pool
        name of zfs pool used to store docker volumes
    zfs_replica_pool
        relative name of zfs pool used to store postgres replica data
    docker_volume_dir
        directory path that docker uses for volumes
    """
    setup_docker_env(docker_volume_dir)
    destroy_exploratory_data_cow(zfs_volume_pool, zfs_replica_pool)
    # Make sure that container doesn't reuse machine's IP address
    execute_sys_command("sudo docker network create --driver=bridge --subnet 172.19.253.0/30 tombstone")
    exploratory_docker_proc, valid = spin_up_exploratory_instance(
        replica_port, exploratory_port, zfs_volume_pool, zfs_replica_pool, docker_volume_dir
    )
    if valid:
        print(execute_sql("CREATE TABLE foo(a int);", EXPLORATION_PORT))
        print(execute_sql("INSERT INTO foo VALUES (42), (666);", EXPLORATION_PORT))
        print(execute_sql("SELECT * FROM foo;", EXPLORATION_PORT))
    else:
        print("Failed to start exploratory instance")
    spin_down_exploratory_instance(exploratory_docker_proc, zfs_volume_pool, zfs_replica_pool, docker_volume_dir)


def spin_up_exploratory_instance(
    replica_port: int, exploratory_port: int, zfs_volume_pool: str, zfs_replica_pool: str, docker_volume_dir: str
) -> Tuple[subprocess.Popen, bool]:
    """
    Start exploratory instance
    Parameters
    ----------
    replica_port
        port that replica instance is reachable from
    exploratory_port
        port that exploratory instance will be reachable from
    zfs_volume_pool
        name of zfs pool used to store docker volumes
    zfs_replica_pool
        relative name of zfs pool used to store postgres replica data
    docker_volume_dir
        directory path that docker uses for volumes
    Returns
    -------
    exploratory_instance
        docker process that is running exploratory instance
    valid
        True if the container started successfully, False otherwise
    """
    print("Taking checkpoint in replica")
    # LOOK HERE: Consider removing this. Checkpointing has limited benefits for data staleness and can have a huge performance cost.
    checkpoint(replica_port)
    print("Checkpoint complete")
    print("Copying replica data")
    copy_pgdata_cow(zfs_volume_pool, zfs_replica_pool)
    print("Replica data copied")
    print("Starting exploratory instance")
    exploratory_docker_proc = start_exploration_docker(docker_volume_dir)
    valid = wait_for_pg_ready(EXPLORATION_CONTAINER_NAME, exploratory_port, exploratory_docker_proc)
    print("Exploratory instance started")
    return exploratory_docker_proc, valid


def spin_down_exploratory_instance(
    exploratory_docker_proc: subprocess.Popen, zfs_volume_pool: str, zfs_replica_pool: str, docker_volume_dir: str
):
    """
    Stop and destroy exploratory instance
    Parameters
    ----------
    exploratory_docker_proc
        docker process that is running exploratory instance
    zfs_volume_pool
        name of zfs pool used to store docker volumes
    zfs_replica_pool
        relative name of zfs pool used to store postgres replica data
    docker_volume_dir
        directory path that docker uses for volumes
    """
    print("Shutting down exploratory instance")
    shutdown_exploratory_docker(exploratory_docker_proc, docker_volume_dir)
    destroy_exploratory_data_cow(zfs_volume_pool, zfs_replica_pool)
    print("Exploratory instance shut down")


if __name__ == "__main__":
    main()
