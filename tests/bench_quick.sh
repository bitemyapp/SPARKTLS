#!/usr/bin/env bash
# Exploratory smoke run; use benchmark.sh for 20 measured repetitions.
# Usage: tests/bench_quick.sh [SECONDS] [runner options]
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SECONDS_ARG=1
if [[ ${1:-} != -* && $# -gt 0 ]]; then SECONDS_ARG=$1; shift; fi
exec python3 "$DIR/benchmarks/run.py" --scenarios handshake x509 \
    --suites TLS_AES_128_GCM_SHA256 --runs 3 --seconds "$SECONDS_ARG" \
    --x509-iters "${X509_ITERS:-500}" "$@"
