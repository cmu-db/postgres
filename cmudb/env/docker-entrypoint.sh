#!/bin/bash

# =====================================================================
# Environment variables.
# =====================================================================

# From the official PostgreSQL Docker image.
# https://hub.docker.com/_/postgres/

POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_INITDB_ARGS=${POSTGRES_INITDB_ARGS}
POSTGRES_INITDB_WALDIR=${POSTGRES_INITDB_WALDIR}
POSTGRES_HOST_AUTH_METHOD=${POSTGRES_HOST_AUTH_METHOD}
PGDATA=${PGDATA}

# From our own Docker image.

BIN_DIR=${BIN_DIR}  # Folder containing all the PostgreSQL binaries.
PGPORT=${PGPORT}    # The port to listen on.

# =====================================================================
# Default environment variable values.
# =====================================================================

if [ -z "$POSTGRES_USER" ]; then
  POSTGRES_USER="noisepage"
fi

if [ -z "$POSTGRES_DB" ]; then
  POSTGRES_DB="noisepage"
fi

if [ -z "$POSTGRES_HOST_AUTH_METHOD" ]; then
  POSTGRES_HOST_AUTH_METHOD="md5"
fi

if [ -z "$PGPORT" ]; then
  PGPORT=15721
fi

# =====================================================================
# Helper functions.
# =====================================================================

_pgctl_start() {
  ${BIN_DIR}/pg_ctl --pgdata=${PGDATA} -w start
}

_pg_stop() {
  ${BIN_DIR}/pg_ctl --pgdata=${PGDATA} -w stop
}

_pg_start() {
  ${BIN_DIR}/postgres "-D" "${PGDATA}" -p 15721
}

_pg_initdb() {
  WALDIR="--waldir=${POSTGRES_INITDB_WALDIR}"
  if [ -z ${POSTGRES_INITDB_WALDIR} ]; then
    WALDIR=""
  fi
  ${BIN_DIR}/initdb --pgdata=${PGDATA} $WALDIR ${POSTGRES_INITDB_ARGS}
}

_pg_config() {
  AUTO_CONF=${PGDATA}/postgresql.auto.conf
  HBA_CONF=${PGDATA}/pg_hba.conf

  echo "listen_addresses = '*'" >> ${AUTO_CONF}
  echo "host all all 0.0.0.0/0 ${POSTGRES_HOST_AUTH_METHOD}" >> ${HBA_CONF}
}

_pg_create_user_and_db() {
  ${BIN_DIR}/psql -c "create user ${POSTGRES_USER} with login password '${POSTGRES_PASSWORD}'" postgres
  ${BIN_DIR}/psql -c "create database ${POSTGRES_DB} with owner = '${POSTGRES_USER}'" postgres
}

_pg_setup_replication() {
  ${BIN_DIR}/psql -c "create user ${NP_REPLICATION_USER} with replication encrypted password '${NP_REPLICATION_PASSWORD}'" postgres
  ${BIN_DIR}/psql -c "select pg_create_physical_replication_slot('replication_slot_replica1')" postgres

}

# All the steps required to start up PostgreSQL.
_pg_start_all() {
  _pg_initdb              # Initialize a new PostgreSQL cluster.
  _pg_config              # Write any configuration options required.
  _pgctl_start            # Start the PostgreSQL cluster.
  _pg_create_user_and_db  # Create the specified user and database.
}

# =====================================================================
# Main logic.
# =====================================================================

main() {
  _pg_start_all
  _pg_stop
  _pg_start
}

main
