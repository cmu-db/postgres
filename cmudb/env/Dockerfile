# NoisePage officially supports Ubuntu 20.04.
FROM ubuntu:20.04

# Suppress interactive dialog.
ARG DEBIAN_FRONTEND=noninteractive

# Copy the official PostgreSQL image for configurable env vars.
# https://hub.docker.com/_/postgres/
ENV POSTGRES_PASSWORD "terrier"
ENV POSTGRES_USER "noisepage"
ENV POSTGRES_DB "noisepage"
ENV POSTGRES_INITDB_ARGS ""
ENV POSTGRES_INITDB_WALDIR ""
ENV POSTGRES_HOST_AUTH_METHOD ""

# PostgreSQL env vars that we customize.
ENV PGDATA "/pgdata"
ENV PGPORT "15721"
# Our own env vars.
# BIN_DIR       :   Destination for PostgreSQL binaries.
ENV BIN_DIR "/home/dev/repo/build/bin"

# Install packages.
COPY ./cmudb/env/packages.sh /packages.sh
RUN \
    apt-get -y update \
    && apt-get -y install sudo \
    && echo y | /packages.sh all

# Create a non-sudo user and switch to them.
# This is because PostgreSQL binaries don't like being
# run as root, e.g., initdb.
RUN adduser --disabled-password --gecos '' dev \
    && adduser dev sudo \
    && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER dev
WORKDIR /home/dev

# Create the directories that PostgreSQL expects.
RUN sudo mkdir -p "$PGDATA" \
    && sudo chown --recursive dev:dev "$PGDATA" \
    && sudo chmod 700 "$PGDATA"

# Copy the contents of the build context (working directory).
COPY --chown=dev:dev . /home/dev/repo

# Configure and build PostgreSQL.
RUN cd /home/dev/repo \
    && bash ./cmudb/build/configure.sh debug \
    && make -j -s \
    && make install -j -s

# Expose the necessary ports.
# EXPOSE 15721

# Copy and set the Docker entrypoint script into the image.
COPY ./cmudb/env/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
