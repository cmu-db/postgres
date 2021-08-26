#!/bin/bash

# Run from the root repo folder.
# configure.sh CONFIGURE_TYPE [CONFIG_DIR] [BUILD_DIR]
#   CONFIGURE_TYPE  : debug, release
#   BUILD_DIR       : Folder that `make install` output should be written to.

CONFIGURE_TYPE="$1"
CONFIGURE_TYPES=("debug" "release")

BUILD_DIR="$2"
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="$(pwd)/build"
fi

CFLAGS_DEBUG="-ggdb -Og -g3 -m64 -fno-omit-frame-pointer"
CFLAGS_RELEASE="-O3 -m64 -march=native"

_parse_configure() {
  # Get the configure type.
  CONFIGURE_FOUND=0
  for key in "${CONFIGURE_TYPES[@]}"; do
    if [ "$key" = "$CONFIGURE_TYPE" ]; then
      CONFIGURE_FOUND=1
    fi
  done
  if [ "$CONFIGURE_FOUND" = "0" ]; then
    echo "Invalid configure type: '$CONFIGURE_TYPE'"
    echo -n "Valid configure types: "
    ( IFS=$' '; echo "${CONFIGURE_TYPES[*]}" )
    exit 1
  fi
}

_configure_debug() {
  set -x
  ./configure CFLAGS="$CFLAGS_DEBUG" --prefix=$BUILD_DIR --enable-debug --enable-cassert --quiet
}

_configure_release() {
  set -x
  ./configure CFLAGS="$CFLAGS_RELEASE" --prefix=$BUILD_DIR --quiet
}

main() {
  set -o errexit

  _parse_configure

  if [ "$CONFIGURE_TYPE" = "debug" ]; then
    _configure_debug
  elif [ "$CONFIGURE_TYPE" = "release" ]; then
    _configure_release
  fi
}

main
