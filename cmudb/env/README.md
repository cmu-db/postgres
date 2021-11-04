The `env` folder is for all files that relate to setting up a development or CI environment.

# Docker tips.

1. Build the Dockerfile image `pgnp`: `sudo docker build --tag pgnp --file ./cmudb/env/Dockerfile .`
2. Run either the:
    - Single-node config: `sudo docker-compose -f cmudb/env/docker-compose-single.yml up`
    - Replicated config: `sudo docker-compose -f cmudb/env/docker-compose-replication.yml up`
3. Once the Docker containers are started up, you can connect to them from the host with `psql -h localhost -U noisepage -p 15721`.
    - The existing docker-compose configuration binds 15721 to the primary (and if relevant, 15722 to the replica).

- You can connect to running instances with `sudo docker exec --interactive --tty INSTANCE_NAME /bin/bash`.
- You can check and modify the docker-compose yml files for passwords, ports, etc.
- You must rebuild the Docker image every time there are changes in your source tree.

# Docker gotchas.

Anything that takes you over 1 day to figure out should be documented here.

- You will not be able to `psql` from the host to the Docker container unless `listen_addresses = '*'` (or similar) is in `postgresql.conf`.