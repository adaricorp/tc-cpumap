#!/bin/bash

set -euo pipefail

/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/common/vmlinux.h
./bpf/libbpf/update.sh
go mod tidy
go generate ./...
