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

# The section below lists custom variables for our project.

# General purpose.
BIN_DIR=${BIN_DIR}  # Folder containing all the PostgreSQL binaries.
PGPORT=${PGPORT}    # The port to listen on.

# Replication.
NP_REPLICATION_TYPE=${NP_REPLICATION_TYPE}          # Must be "primary" or "replica"
NP_REPLICATION_USER=${NP_REPLICATION_USER}          # Replication user.
NP_REPLICATION_PASSWORD=${NP_REPLICATION_PASSWORD}  # Replication password.

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

  # pg_hba.conf
  echo "host all all 0.0.0.0/0 ${POSTGRES_HOST_AUTH_METHOD}" >> ${HBA_CONF}

  # postgresql.auto.conf
  # Allow Docker host to connect to container.
  echo "listen_addresses = '*'" >> ${AUTO_CONF}
}

_pg_create_user_and_db() {
  ${BIN_DIR}/psql -c "create user ${POSTGRES_USER} with login password '${POSTGRES_PASSWORD}'" postgres
  ${BIN_DIR}/psql -c "create database ${POSTGRES_DB} with owner = '${POSTGRES_USER}'" postgres
  # Enable monitoring for the created user.
  ${BIN_DIR}/psql -c "grant pg_monitor to ${POSTGRES_USER}" postgres
}

_pg_setup_replication() {
  AUTO_CONF=${PGDATA}/postgresql.auto.conf
  HBA_CONF=${PGDATA}/pg_hba.conf

  # See PostgreSQL docs for complete description of parameters.

  # wal_level: How much information to ship over.
  echo "wal_level = replica" >> ${AUTO_CONF}
  # hot_standby: True to enable connecting and running queries during recovery.
  echo "hot_standby = on" >> ${AUTO_CONF}
  # max_wal_senders: Maximum number of concurrent connections to standby/backup clients.
  echo "max_wal_senders = 10" >> ${AUTO_CONF}
  # max_replication_slots: Maximum number of replication slots.
  echo "max_replication_slots = 10" >> ${AUTO_CONF}
  # hot_standby_feedback: True if standby should tell primary about what queries are currently executing.
  echo "hot_standby_feedback = on" >> ${AUTO_CONF}

  if [ "${NP_REPLICATION_TYPE}" = "primary" ]; then
    # ===============================
    # Enable replication.
    # ===============================

    # Create replication user.
    ${BIN_DIR}/psql -c "create user ${NP_REPLICATION_USER} with replication encrypted password '${NP_REPLICATION_PASSWORD}'" postgres
    # Allow replication user to connect..
    echo "host replication ${NP_REPLICATION_USER} 0.0.0.0/0 md5" >> ${HBA_CONF}
    # Reload configuration.
    ${BIN_DIR}/psql -c "select pg_reload_conf()" postgres
    # Create replication slot for replica.
    ${BIN_DIR}/psql -c "select pg_create_physical_replication_slot('replication_slot_replica1')" postgres
  fi
}

# All the steps required to start up PostgreSQL.
_pg_start_all() {
  _pg_initdb              # Initialize a new PostgreSQL cluster.
  _pg_config              # Write any configuration options required.
  _pgctl_start            # Start the PostgreSQL cluster.
  _pg_create_user_and_db  # Create the specified user and database.

  if [ ! -z "${NP_REPLICATION_TYPE}" ]; then
    _pg_setup_replication
  fi
}

# =====================================================================
# Main logic.
# =====================================================================

main() {
  # Only initdb if this is not a replica. The replica will recover from backup.
  if [ ! "${NP_REPLICATION_TYPE}" = "replica" ]; then
    # This is a single-node or the primary.
    _pg_start_all
    _pg_stop
    _pg_start
  else
    # This is a replica.
    while true ; do
      # Note that there is a potential race here where the primary restarts and healthcheck succeeds.
      sleep 10
      ${BIN_DIR}/pg_isready --host primary --port 15721 --username noisepage
      READY_CHECK=$?
      if [ "$READY_CHECK" = "0" ]; then
        break
      fi
    done

    rm -rf ${PGDATA}/*
    # Initialize replica backup from primary.
    echo passyMcPassword | ${BIN_DIR}/pg_basebackup --host primary --username replicator --port 15721 --pgdata=${PGDATA} --format=p --wal-method=stream --progress --write-recovery-conf --slot replication_slot_replica1
    _pg_start
  fi
}

main
