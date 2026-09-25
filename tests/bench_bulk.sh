#!/usr/bin/env bash
# Usage: tests/bench_bulk.sh [SECONDS [BYTES]] [runner options]
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SECONDS_ARG=2
SIZE_ARG=16777216
if [[ ${1:-} != -* && $# -gt 0 ]]; then SECONDS_ARG=$1; shift; fi
if [[ ${1:-} != -* && $# -gt 0 ]]; then SIZE_ARG=$1; shift; fi
exec python3 "$DIR/benchmarks/run.py" --scenarios bulk \
    --seconds "$SECONDS_ARG" --size "$SIZE_ARG" "$@"
