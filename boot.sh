#!/bin/bash

set -euo pipefail

btf_file="/sys/kernel/btf/vmlinux"
if [ -e "/sys/kernel/btf/nf_conntrack" ]; then
    btf_file="/sys/kernel/btf/nf_conntrack"
fi

/usr/sbin/bpftool btf dump file "${btf_file}" format c >"bpf/common/vmlinux.h"
./bpf/libbpf/update.sh
go mod tidy
go generate ./...
