# Exploratory Daemon
The exploratory daemon exposes the functionality to take online 
copies of a postgres database. The goal of the copy is to be able 
to run fast but not necessarily have the most up to date data. 
The process of taking a copy is the following:

1. Run checkpoint on original database (This is not strictly required).
2. Take a ZFS snapshot and clone of pgdata directory.
3. Run pg_resetwal on ZFS copy. This will prune the log to some 
consistent point which makes starting the new instance much faster. 
However it also results in some lost data.
5. Start exploratory docker container which uses the copied pgdata 
directory to start a postgres instance.

The process of tearing down an exploratory instance is the
following:

1. Stop postgres instance.
2. Shutdown docker container.
3. Delete copied data.

The daemon needs to be run on a system with an existing postgres
instance and ZFS installed.

The current implementation just takes a single copy, runs some
random queries, and tears down the copy. In the future this
functionality will be daemonized to allow on demand copies to
be made.

## Example Setup Guide
Look at the python documentation for the `main` function in 
`exploratory_daemon.py` to see the requirements in order for the 
exploratory daemon to work with ZFS. There are multiple ways to 
accomplish these requirements. Below is a more in depth guide for 
one of the ways to set up postgres to work with the exploratory daemon.
It will start a primary and replica postgres instance on the same machine,
using the same disk with a ZFS filesystem. 

1. Install ZFS on a disk. For this guide let's assume the disk's name is `nvme0n1`.
2. Create ZFS pool for docker somewhere on the disk. For this guide we'll use the path `/mnt/docker` Ex: `sudo zpool create -f zpool-docker -m /mnt/docker /dev/nvme0n1`.
3. Create ZFS filesystem for docker volumes needed. Ex: 
```bash
sudo zfs create zpool-docker/volumes
sudo zfs create zpool-docker/volumes/pgdata-primary
sudo zfs create zpool-docker/volumes/pgdata-replica
```
4. Change the Docker startup `--data-root` parameter to use ZFS volume. You will need to find where the `docker.service` file is located and change the `dockerd` command in it to use the `data-root` parameter with the ZFS pool file path as the value.
  -  `dockerd` documentation can be found here: [https://docs.docker.com/engine/reference/commandline/dockerd/](https://docs.docker.com/engine/reference/commandline/dockerd/).
  -  The `docker.service` file is usually found at `/lib/systemd/system/docker.service`.
  -  Using the previous examples the parameter should look like: `--data-root /mnt/docker`.
  -  This Stack Overflow post explains how to do this: [https://stackoverflow.com/questions/36014554/how-to-change-the-default-location-for-docker-create-volume-command](https://stackoverflow.com/questions/36014554/how-to-change-the-default-location-for-docker-create-volume-command)
  -  You may need to restart Docker after this.
5. Create primary and replica Docker volumes. Ex:
```bash
sudo docker volume create pgdata-primary
sudo docker volume create pgdata-replica
```
  - May need to run `chown -R` on the volume directories. Ex: `sudo chown -R 1000:1000 /mnt/docker/volumes/pgdata-primary && sudo chown -R 1000:1000 /mnt/docker/volumes/pgdata-replica`
6. OPTIONAL: If you are running this on a dev machine you may want to create a network tombstone. Ex: `sudo docker network create --driver=bridge --subnet 172.19.253.0/30 tombstone`
7. Start primary and replica postgres servers using docker compose. Ex: `sudo docker-compose -p replication -f cmudb/env/docker-compose-replication.yml up`

Once the postgres servers are up you can start inserting data in them and run the exploratory daemon at any point.
