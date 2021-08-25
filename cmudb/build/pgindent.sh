#!/bin/bash

# Run this script from the root folder of your repo.

set -e

ROOT_FOLDER=$(pwd)

# Combine the typedefs into a single file.
#   typedefs.list.old                 : Old PostgreSQL typedefs list.
#   typedefs-missing-postgres.list    : Missing typedefs from PostgreSQL.
#   typedefs-noisepage.list           : New typedefs added in NoisePage.
#   typedefs.list                     : Hardcoded pgindent default destination.
cp $ROOT_FOLDER/src/tools/pgindent/typedefs.list.old $ROOT_FOLDER/src/tools/pgindent/typedefs.list
cat \
  $ROOT_FOLDER/src/tools/pgindent/typedefs-missing-postgres.list \
  | sort | uniq >> $ROOT_FOLDER/src/tools/pgindent/typedefs.list
cat \
  $ROOT_FOLDER/src/tools/pgindent/typedefs-noisepage.list \
  | sort | uniq >> $ROOT_FOLDER/src/tools/pgindent/typedefs.list

# Run pgindent.
perl $ROOT_FOLDER/src/tools/pgindent/pgindent
