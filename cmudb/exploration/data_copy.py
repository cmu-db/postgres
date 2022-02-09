from util import EXPLORATION_VOLUME_POOL, ZFS_SNAPSHOT_NAME, execute_sys_command

# ZFS Functionality


def zfs_create_snapshot(zfs_pool: str, snapshot_name: str):
    """
    Creates a ZFS snapshot
    Parameters
    ----------
    zfs_pool
        name of zfs to snapshot
    snapshot_name
        name of snapshot
    """
    execute_sys_command(f"sudo zfs snapshot {zfs_pool}@{snapshot_name}")


def zfs_destroy_snapshot(zfs_snapshot: str):
    """
    Destroys a ZFS snapshot
    Parameters
    ----------
    zfs_snapshot
        name of zfs to snapshot to destroy
    """
    execute_sys_command(f"sudo zfs destroy {zfs_snapshot}")


def zfs_clone_snapshot(zfs_snapshot: str, clone_pool_name: str):
    """
    Clone a ZFS snapshot
    Parameters
    ----------
    zfs_snapshot
        name of zfs to snapshot to clone
    clone_pool_name
        name of pool to store clone
    """
    execute_sys_command(f"sudo zfs clone {zfs_snapshot} {clone_pool_name}")


def zfs_destroy_pool(pool_name: str):
    """
    Destroy ZFS pool
    Parameters
    ----------
    pool_name
        name of zfs pool to destroy
    """
    execute_sys_command(f"sudo zfs destroy {pool_name}")


# Exploratory Data


def copy_pgdata_cow(zfs_volume_pool: str, zfs_replica_pool: str):
    """
    Copy replica instance's data for use by the exploratory instance
    Parameters
    ----------
    zfs_volume_pool
        name of zfs pool used to store docker volumes
    zfs_replica_pool
        relative name of zfs pool used to store postgres replica data
    """
    zfs_create_snapshot(f"{zfs_volume_pool}/{zfs_replica_pool}", ZFS_SNAPSHOT_NAME)
    zfs_clone_snapshot(
        f"{zfs_volume_pool}/{zfs_replica_pool}@{ZFS_SNAPSHOT_NAME}", f"{zfs_volume_pool}/{EXPLORATION_VOLUME_POOL}"
    )


def destroy_exploratory_data_cow(zfs_volume_pool: str, zfs_replica_pool: str):
    """
    Destroy exploratory instance's data
    Parameters
    ----------
    zfs_volume_pool
        name of zfs pool used to store docker volumes
    zfs_replica_pool
        relative name of zfs pool used to store postgres replica data
    """
    zfs_destroy_pool(f"{zfs_volume_pool}/{EXPLORATION_VOLUME_POOL}")
    zfs_destroy_snapshot(f"{zfs_volume_pool}/{zfs_replica_pool}@{ZFS_SNAPSHOT_NAME}")
