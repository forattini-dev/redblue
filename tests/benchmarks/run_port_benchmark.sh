#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domain-or-ip> [nmap_preset] [rb_preset]" >&2
  exit 1
fi

TARGET=$1
NMAP_PRESET=${2:-${NMAP_PRESET:-top100}}
RB_PRESET=${3:-${RB_PRESET:-common}}
OUTPUT_DIR=${OUTPUT_DIR:-$(pwd)/tests/benchmarks/results}
THREADS_DEFAULT=${RB_THREADS:-100}
TIMEOUT_DEFAULT=${RB_TIMEOUT:-1000}

mkdir -p "$OUTPUT_DIR"

HOST=$TARGET
if [[ ! $TARGET =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Resolving $TARGET using rb dns..."
  if command -v rb >/dev/null; then
    RESOLVE_OUTPUT=$(rb dns record resolve "$TARGET" 2>&1 || true)
    HOST=$(echo "$RESOLVE_OUTPUT" | awk '/→/ {print $3; exit}')
    if [[ -z $HOST ]]; then
      echo "[WARNING] Could not resolve $TARGET via rb. Falling back to original target." >&2
      HOST=$TARGET
    else
      echo "Resolved $TARGET -> $HOST"
    fi
  else
    echo "[WARNING] rb not found in PATH. Skipping resolution." >&2
  fi
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PATH="$SCRIPT_DIR/../../target/release:$PATH" \
  HOST="$HOST" \
  NMAP_PRESET="$NMAP_PRESET" \
  RB_PRESET="$RB_PRESET" \
  RB_THREADS="$THREADS_DEFAULT" \
  RB_TIMEOUT="$TIMEOUT_DEFAULT" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  "$SCRIPT_DIR/nmap_vs_rb.sh"
