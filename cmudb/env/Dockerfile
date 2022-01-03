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
# NoisePage env vars.
# BIN_DIR       :   Destination for PostgreSQL binaries.
ENV BIN_DIR "/home/terrier/repo/build/bin"

ENV http_proxy "http://proxy.pdl.cmu.edu:3128/"
ENV https_proxy "http://proxy.pdl.cmu.edu:3128/"

# Install packages.
COPY ./cmudb/env/apt_for_pdl.conf /etc/apt/apt.conf
COPY ./cmudb/env/packages.sh /packages.sh
COPY ./cmudb/env/.docker /home/terrier/.docker
RUN \
    apt-get -y update \
    && apt-get -y install sudo \
    && echo y | /packages.sh all

# Create a non-sudo user and switch to them.
# This is because PostgreSQL binaries don't like being
# run as root, e.g., initdb.
RUN adduser --disabled-password --gecos '' terrier \
    && adduser terrier sudo \
    && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER terrier
WORKDIR /home/terrier

# Create the directories that PostgreSQL expects.
RUN sudo mkdir -p "$PGDATA" \
    && sudo chown --recursive terrier:terrier "$PGDATA" \
    && sudo chmod 700 "$PGDATA"


# Copy the contents of the build context (working directory).
COPY --chown=terrier:terrier . /home/terrier/repo

# Configure and build NoisePage.
RUN cd /home/terrier/repo \
    && bash ./cmudb/build/configure.sh release \
    && make -j -s \
    && make install -j -s

# Document that the following ports need to be exposed.
# Note that the ports are not actually exposed unless the relevant
# -p or -P flag is given to docker run, see Docker documentation.
EXPOSE 15721

# Copy and set the Docker entrypoint script into the image.
COPY ./cmudb/env/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
