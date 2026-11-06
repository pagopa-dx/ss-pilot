#!/usr/bin/env bash
set -euo pipefail

operation="${1:?Specify start or stop}"
evidence_dir="${2:?Specify an evidence directory}"

case "$operation" in
  start)
    command -v tcpdump
    mkdir -p "$evidence_dir"
    sudo tcpdump --immediate-mode -i any -nn -l -s 512 \
      '(udp port 53 or tcp port 53)' \
      > "$evidence_dir/dns.log" 2> "$evidence_dir/tcpdump.stderr" &
    pid=$!
    printf 'PILOT_CAPTURE_PID=%s\n' "$pid" >> "$GITHUB_ENV"
    sleep 1
    if ! sudo kill -0 "$pid" 2>/dev/null; then
      cat "$evidence_dir/tcpdump.stderr" >&2
      echo "::error::DNS capture did not start."
      exit 1
    fi
    ;;
  stop)
    pid="${PILOT_CAPTURE_PID:?DNS capture PID is missing}"
    if [[ ! "$pid" =~ ^[0-9]+$ ]] || (( pid <= 1 )); then
      echo "::error::Invalid DNS capture PID."
      exit 1
    fi
    if ! sudo kill -0 "$pid" 2>/dev/null; then
      echo "::error::DNS capture exited before collection finished."
      exit 1
    fi
    sudo kill -INT "$pid"
    for _ in {1..10}; do
      if ! sudo kill -0 "$pid" 2>/dev/null; then
        cat "$evidence_dir/tcpdump.stderr"
        exit 0
      fi
      sleep 1
    done
    sudo kill -TERM "$pid"
    echo "::error::DNS capture did not stop cleanly."
    exit 1
    ;;
  *)
    echo "::error::Unsupported DNS capture operation: $operation"
    exit 1
    ;;
esac
