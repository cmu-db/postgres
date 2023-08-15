#!/bin/bash

set -euxo pipefail

BUILD_DIR="$(pwd)/build/postgres/"
BIN_DIR="$(pwd)/build/postgres/bin/"
POSTGRES_USER="noisepage_user"
POSTGRES_PASSWORD="noisepage_pass"
POSTGRES_DB="noisepage_db"
POSTGRES_PORT=15721

ROOT_DIR=$(pwd)

mkdir -p "${BUILD_DIR}"
echo "You may want to comment out the configure step if you're not regularly switching between debug and release."
#./cmudb/build/configure.sh debug "${BUILD_DIR}"
make install -j
rm -rf "${BIN_DIR}"/pgdata
"${BIN_DIR}"/initdb -D "${BIN_DIR}"/pgdata
cp ./cmudb/env/pgtune.auto.conf "${BIN_DIR}"/pgdata/postgresql.auto.conf

cd ./cmudb/extensions/db721_fdw/
make clean
make install -j
make clean
cd "${ROOT_DIR}"
echo -e "\nshared_preload_libraries = 'db721_fdw'\n" >>"${BIN_DIR}"/pgdata/postgresql.auto.conf

"${BIN_DIR}"/postgres -D "${BIN_DIR}"/pgdata -p ${POSTGRES_PORT}
