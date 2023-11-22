#!/bin/bash

set -euo pipefail

curl -sfL https://goreleaser.com/static/run | \
  bash -s -- release --clean --skip=publish --snapshot
