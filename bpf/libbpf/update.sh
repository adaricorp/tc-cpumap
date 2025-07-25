#!/usr/bin/env bash

set -euo pipefail

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.5.1

# The headers we want
prefix="libbpf-${LIBBPF_VERSION}"
headers=(
    "$prefix"/LICENSE.BSD-2-Clause
    "$prefix"/src/bpf_endian.h
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
    "$prefix"/src/bpf_tracing.h
)

libbpf_dir=$(dirname "$0")

# Fetch libbpf release and extract the desired headers
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" |
    tar -C "${libbpf_dir}" -xz --xform='s#.*/##' "${headers[@]}"
