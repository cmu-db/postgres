import subprocess
from typing import AnyStr, Tuple

from util import (
    ENV_FOLDER,
    EXPLORATION_VOLUME_POOL,
    EXPLORATORY_COMPOSE,
    EXPLORATORY_PROJECT_NAME,
    IMAGE_TAG,
    PROJECT_ROOT,
    OutputStrategy,
    execute_sys_command,
    stop_process,
)

# TODO use docker library (https://github.com/docker/docker-py)

# Docker Utilities


def build_image(tag: str):
    """
    Build docker image
    Parameters
    ----------
    tag
        tag of docker image
    """
    execute_sys_command(f"sudo docker build --tag {tag} --file {ENV_FOLDER}/Dockerfile {PROJECT_ROOT}")


def create_volume(docker_volume_dir: str, volume_name: str):
    """
    Create a docker volume
    Parameters
    ----------
    docker_volume_dir
        directory path that docker uses for volumes
    volume_name
        name of docker volume to remove
    """
    # docker_volume_dir. pylint: disable=unused-argument
    execute_sys_command(f"sudo docker volume create {volume_name}")


def remove_volume(volume_name: str):
    """
    Removes a docker volume
    Parameters
    ----------
    volume_name
        name of docker volume to remove
    """
    execute_sys_command(f"sudo docker volume rm {volume_name}")


def create_container(compose_yml: str, project_name: str) -> subprocess.Popen:
    """
    Create docker container
    Parameters
    ----------
    compose_yml
        name of docker compose file
    project_name
        name of docker compose project
    Returns
    -------
    container
        docker container process
    """
    compose, _, _ = execute_sys_command(
        f"sudo docker-compose -p {project_name} -f {ENV_FOLDER}/{compose_yml} up",
        block=False,
        output_strategy=OutputStrategy.PRINT,
    )
    return compose


def stop_container(container: subprocess.Popen):
    """
    Stop docker container
    Parameters
    ----------
    container
        docker container process
    """
    stop_process(container)


def destroy_container(compose_yml: str, project_name: str):
    """
    Destroy docker container
    Parameters
    ----------
    compose_yml
        name of docker compose file
    project_name
        name of docker compose project
    """
    execute_sys_command(f"sudo docker-compose -p {project_name} -f {ENV_FOLDER}/{compose_yml} down --volumes")


def execute_in_container(
    container_name: str, cmd: str, block: bool = True, output_strategy: OutputStrategy = OutputStrategy.PRINT
) -> Tuple[subprocess.Popen, AnyStr, AnyStr]:
    """
    Execute bash command in docker container
    Parameters
    ----------
    container_name
        name of docker container
    cmd
        command to execute
    block
        whether or not to block until command is complete
    output_strategy
        strategy for handling command output
    Returns
    -------
    process
        process running command
    stdout
        stdout if block is True and output_strategy is Capture
    stderr
        stderr if block is True and output_strategy is Capture
    """
    docker_cmd = f"docker exec {container_name} /bin/bash -c".split(" ")
    docker_cmd.append(f"{cmd}")

    return execute_sys_command(docker_cmd, block=block, output_strategy=output_strategy)


# Exploratory functionality


def setup_docker_env(docker_volume_dir: str):
    """
    Setup docker environment. Delete any old docker instances and volumes and build docker image.
    Parameters
    ----------
    docker_volume_dir
        directory path that docker uses for volumes
    """
    cleanup_docker_env(docker_volume_dir)
    build_image(IMAGE_TAG)


def cleanup_docker_env(docker_volume_dir: str):
    """
    Delete any old docker instances and volumes.
    Parameters
    ----------
    docker_volume_dir
        directory path that docker uses for volumes
    """
    destroy_container(EXPLORATORY_COMPOSE, EXPLORATORY_PROJECT_NAME)
    remove_exploratory_data(docker_volume_dir)
    remove_volume(EXPLORATION_VOLUME_POOL)


def start_exploration_docker(docker_volume_dir: str) -> subprocess.Popen:
    """
    Start exploratory docker container
    Parameters
    ----------
    docker_volume_dir
        directory path that docker uses for volumes
    Returns
    -------
    exploratory_docker_process
        process running exploratory docker container
    """
    create_volume(docker_volume_dir, EXPLORATION_VOLUME_POOL)
    compose = create_container(EXPLORATORY_COMPOSE, EXPLORATORY_PROJECT_NAME)
    return compose


def shutdown_exploratory_docker(exploratory_docker_process: subprocess.Popen, docker_volume_dir: str):
    """
    Shutdown exploratory docker container
    Parameters
    ----------
    exploratory_docker_process
        process running exploratory docker container
    docker_volume_dir
        directory path that docker uses for volumes
    """
    stop_container(exploratory_docker_process)
    cleanup_docker_env(docker_volume_dir)


def remove_exploratory_data(docker_volume_dir: str):
    """
    Remove all postgres data from exploratory instance
    Parameters
    ----------
    docker_volume_dir
        directory path that docker uses for volumes
    """
    execute_sys_command(f"sudo rm -rf {docker_volume_dir}/{EXPLORATION_VOLUME_POOL}")
