#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p results/logs
mkdir -p results/extract
exec 9>results/extract/.overnight.lock
if ! flock -n 9; then
  echo "Another overnight extraction is already running" >&2
  exit 1
fi
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log="results/logs/overnight_${timestamp}.log"
echo "Log: $PWD/$log"
exec systemd-inhibit --what=sleep:idle --why="Memory gate overnight extraction" \
  python3 -u -m harness.overnight >"$log" 2>&1
