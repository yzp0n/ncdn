#!/bin/bash
set -e

# FIXME: reflex should restart supervisord prog
# export MAYBE_REFLEX="reflex -r '\.go$' -s -- "

export SRC_DIR=$(readlink -f $(dirname $0))
export LOG_DIR=/tmp/log
mkdir -p ${LOG_DIR}

cd ${SRC_DIR}
supervisord -c ./supervisord.conf
