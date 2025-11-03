#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
NMAP_PRESET="${NMAP_PRESET:-top100}" # top100 (nmap), full, custom
RB_PRESET="${RB_PRESET:-common}"
OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)/tests/benchmarks/results}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

mkdir -p "$OUTPUT_DIR"

if ! command -v nmap >/dev/null; then
  echo "[ERROR] nmap not found. Install nmap before running benchmarks." >&2
  exit 1
fi

if ! command -v rb >/dev/null; then
  echo "[ERROR] rb CLI not found in PATH." >&2
  exit 1
fi

case "$NMAP_PRESET" in
  top100)
    NMAP_PORTS="--top-ports 100"
    ;;
  full)
    NMAP_PORTS="-p-"
    ;;
  custom)
    NMAP_PORTS="${NMAP_PORTS:-}" # user must provide NMAP_PORTS env
    if [ -z "$NMAP_PORTS" ]; then
      echo "[ERROR] custom preset selected but NMAP_PORTS not set." >&2
      exit 1
    fi
    ;;
  *)
    echo "[ERROR] unknown NMAP_PRESET: $NMAP_PRESET" >&2
    exit 1
    ;;
esac

RB_THREADS="${RB_THREADS:-100}"
RB_TIMEOUT="${RB_TIMEOUT:-1000}"

NMAP_OUT="$OUTPUT_DIR/nmap-${HOST//\//_}-${TIMESTAMP}.txt"
RB_OUT="$OUTPUT_DIR/rb-${HOST//\//_}-${TIMESTAMP}.txt"
SUMMARY="$OUTPUT_DIR/summary-${HOST//\//_}-${TIMESTAMP}.txt"

cat <<INFO
== Benchmark: nmap vs rb ==
Target      : $HOST
nmap preset : $NMAP_PRESET ($NMAP_PORTS)
rb preset   : $RB_PRESET (--threads $RB_THREADS --timeout $RB_TIMEOUT)
Output dir  : $OUTPUT_DIR
INFO

start=$(date +%s)
nmap $NMAP_PORTS -Pn "$HOST" | tee "$NMAP_OUT"
nmap_end=$(date +%s)

rb network ports scan "$HOST" --preset "$RB_PRESET" --threads "$RB_THREADS" --timeout "$RB_TIMEOUT" | tee "$RB_OUT"
rb_end=$(date +%s)

nmap_duration=$((nmap_end - start))
rb_duration=$((rb_end - nmap_end))

{
  echo "Benchmark summary ($TIMESTAMP)"
  echo "Target      : $HOST"
  echo "nmap output : $(basename "$NMAP_OUT") ($nmap_duration s)"
  echo "rb output   : $(basename "$RB_OUT") ($rb_duration s)"
  echo "nmap preset : $NMAP_PRESET"
  echo "rb preset   : $RB_PRESET"
} | tee "$SUMMARY"

echo "Saved:"
echo "  $NMAP_OUT"
echo "  $RB_OUT"
echo "  $SUMMARY"

echo "Done. Review outputs to compare open/closed ports." 
