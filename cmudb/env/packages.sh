#!/bin/bash

## =================================================================
## NOISEPAGE PACKAGE INSTALLATION
##
## This script will install all the packages that are needed to
## build and run the DBMS.
##
## Supported environments:
##  * Ubuntu 20.04
## =================================================================


# PostgreSQL packages: https://wiki.postgresql.org/wiki/Compile_and_Install_from_source_code
LINUX_BUILD_PACKAGES=(\
  "bison" \             # PostgreSQL.
  "build-essential" \   # PostgreSQL.
  "flex" \              # PostgreSQL.
  "libreadline-dev" \   # PostgreSQL.
  "libssl-dev" \        # PostgreSQL.
  "libxml2-dev" \       # PostgreSQL.
  "libxml2-utils" \     # PostgreSQL.
  "libxslt-dev" \       # PostgreSQL.
  "pg-bsd-indent" \     # pg_bsd_indent. Needed by pgindent.
  "xsltproc" \          # PostgreSQL.
  "zlib1g-dev" \        # PostgreSQL.
)

main() {
  set -o errexit

  INSTALL_TYPE="$1"
  if [ -z "$INSTALL_TYPE" ]; then
    INSTALL_TYPE="all"
  fi
  ALLOWED=("all")
  FOUND=0
  for key in "${ALLOWED[@]}"; do
    if [ "$key" == "$INSTALL_TYPE" ] ; then
      FOUND=1
    fi
  done
  if [ "$FOUND" = "0" ]; then
    echo "Invalid installation type '$INSTALL_TYPE'"
    echo -n "Allowed Values: "
    ( IFS=$' '; echo "${ALLOWED[*]}" )
    exit 1
  fi
  
  echo "PACKAGES WILL BE INSTALLED. THIS MAY BREAK YOUR EXISTING TOOLCHAIN."
  echo "YOU ACCEPT ALL RESPONSIBILITY BY PROCEEDING."
  echo
  echo "INSTALLATION TYPE: $INSTALL_TYPE"
  read -p "Proceed? [Y/n] : " yn
  case $yn in
      Y|y) install;;
      *) ;;
  esac

  echo "Script complete."
}

give_up() {
  set +x
  OS=$1
  VERSION=$2
  [ ! -z "$VERSION" ] && VERSION=" $VERSION"
  
  echo
  echo "Unsupported distribution '${OS}${VERSION}'"
  echo "Please contact our support team for additional help."
  echo "Be sure to include the contents of this message."
  echo "Platform: $(uname -a)"
  echo
  echo "https://github.com/cmu-db/noisepage/issues"
  echo
  exit 1
}

install() {
  set -x
  UNAME=$(uname | tr "[:lower:]" "[:upper:]" )
  VERSION=""

  case $UNAME in
    LINUX)
      DISTRO=$(cat /etc/os-release | grep '^ID=' | cut -d '=' -f 2 | tr "[:lower:]" "[:upper:]" | tr -d '"')
      VERSION=$(cat /etc/os-release | grep '^VERSION_ID=' | cut -d '"' -f 2)
      
      # We only support Ubuntu right now
      [ "$DISTRO" != "UBUNTU" ] && give_up $DISTRO $VERSION
      
      # Check Ubuntu version
      case $VERSION in
        20.04) install_linux ;;
        *) give_up $DISTRO $VERSION;;
      esac
      ;;

    *) give_up $UNAME $VERSION;;
  esac
}

setup_apt_postgres() {
  sudo --preserve-env apt-get -y install curl ca-certificates gnupg lsb-release
  curl https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg >/dev/null
  sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
  sudo --preserve-env apt-get -y update
}

install_linux() {
  setup_apt_postgres

  # Update apt-get.
  apt-get -y update
  
  # Install packages. Note that word splitting is desired behavior.
  if [ "$INSTALL_TYPE" = "all" ]; then
    apt-get -y install $( IFS=$' '; echo "${LINUX_BUILD_PACKAGES[*]}" )
  fi
}

main "$@"
