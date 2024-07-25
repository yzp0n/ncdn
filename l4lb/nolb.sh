#!/bin/bash

# exit if I'm not root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

echo "For bisecting, setup ipip tunnel instead of LB..."
set -x

ip -n LB l set net0 xdp off

ip -n LB tunnel a ipip0 remote 192.168.88.10 local 192.168.88.20 dev net0
ip -n LB l set ipip0 up
ip -n LB r add 192.0.2.0/24 dev ipip0
