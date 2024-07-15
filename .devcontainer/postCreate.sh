#!/bin/bash

sudo apt update
sudo apt install --no-install-recommends -y \
    libssl-dev sshpass dnsutils \
    supervisor iputils-ping tcpdump bind9-dnsutils

# build-essential libbpf-dev clang llvm linux-headers-amd64

go install github.com/cespare/reflex@latest
