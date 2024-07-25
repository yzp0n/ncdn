#!/bin/bash
set -e

export MY_USER=${USER}
export SRC_DIR=$(readlink -f $(dirname $0)/..)
export BIN_DIR=/tmp/ncdn-bin
mkdir -p ${BIN_DIR}
export LOG_DIR=/tmp/log
mkdir -p ${LOG_DIR}

set -x
go build -o ${BIN_DIR}/origin ${SRC_DIR}/origin
go build -o ${BIN_DIR}/popcache ${SRC_DIR}/popcache
set +x

cd ${SRC_DIR}/l4lb
sudo -E supervisord -c ./supervisord.conf
