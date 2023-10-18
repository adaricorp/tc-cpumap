#!/bin/bash

set -euo pipefail

export CGO_ENABLED=0

/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/common/vmlinux.h
./bpf/libbpf/update.sh

go generate ./...

mkdir -p dist
for cmd in cmd/*; do
    cmd_name=$(basename "${cmd}")
    if [ "${cmd_name}" != "tc_cpumap" ]; then
        cmd_name="tc_cpumap_${cmd_name}"
    fi
    (cd dist && go build -o "${cmd_name}" "../${cmd}")
done
