#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p results/dev/logs results/dev/extract
exec 9>results/dev/extract/.overnight.lock
if ! flock -n 9; then
  echo "Another dev extraction is already running" >&2
  exit 1
fi
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log="results/dev/logs/overnight_${timestamp}.log"
echo "Log: $PWD/$log"
exec systemd-inhibit --what=sleep:idle --why="Memory gate dev extraction" \
  python3 -u -m harness.overnight --dataset dev >"$log" 2>&1
