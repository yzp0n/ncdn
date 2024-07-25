#!/bin/bash
set -e

export SRC_DIR=$(readlink -f $(dirname $0)/..)
export BIN_DIR=/tmp/ncdn-bin
mkdir -p ${BIN_DIR}

set -x
(cd ${SRC_DIR}/l4lb/c && make)
set +x

cd ${SRC_DIR}/l4lb
go test -exec sudo ./l4lbdrv "$@"
