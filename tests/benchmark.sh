#!/usr/bin/env bash
# Repeated handshake and X.509 comparisons; see benchmarks/README.md.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/benchmarks/run.py" --scenarios handshake x509 "$@"
