#!/bin/bash
set -e

export MY_USER=${USER}
export SRC_DIR=$(readlink -f $(dirname $0)/..)
export BIN_DIR=/tmp/ncdn-bin
mkdir -p ${BIN_DIR}

set -x
(cd ${SRC_DIR}/l4lb/c && make)
go build -o ${BIN_DIR}/l4lb ${SRC_DIR}/l4lb/cmd
set +x

cd ${SRC_DIR}/l4lb

dests=""

# for ns in LB C0 C1; do
for ns in LB C0; do
    ip4=$(sudo ip netns exec ${ns} ip -json -f inet a show net0 | jq '.[].addr_info[].local' -r)
    mac=$(sudo ip netns exec ${ns} cat /sys/class/net/net0/address)

    dests="${dests}${ip4};${mac},"
done

echo ${dests}

sudo ip -n LB tunn del ipip0 || echo "no ipip0. good" # in case it exists from a `nolb.sh` run
sudo ip netns exec LB ${BIN_DIR}/l4lb -xdpcapHookPath="" -dests="${dests}"
