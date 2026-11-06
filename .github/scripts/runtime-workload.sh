#!/usr/bin/env bash
set -euo pipefail

mode="${1:?Specify audit or block}"
evidence_dir="${2:?Specify an evidence directory}"
case "$mode" in
  audit|block) ;;
  *) echo "::error::Unsupported workload mode: $mode"; exit 1 ;;
esac

mkdir -p "$evidence_dir"
: > "$evidence_dir/workload.jsonl"

for domain in api.github.com example.com; do
  url="https://${domain}/"
  if [[ "$domain" == api.github.com ]]; then
    url="${url}zen"
  fi
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  curl --proto '=https' --tlsv1.2 --silent --show-error \
    --connect-timeout 10 --max-time 15 \
    --output /dev/null --write-out '%{http_code}' "$url" \
    > "$evidence_dir/${domain}.http" 2> "$evidence_dir/${domain}.stderr" &
  pid=$!
  if wait "$pid"; then
    result=0
  else
    result=$?
  fi
  http_status="$(cat "$evidence_dir/${domain}.http")"
  cat "$evidence_dir/${domain}.stderr" >&2
  printf '%s: HTTP %s, curl exit %s, pid %s\n' "$url" "$http_status" "$result" "$pid"
  python3 - "$domain" "$result" "$http_status" "$pid" "$started_at" \
    >> "$evidence_dir/workload.jsonl" <<'PY'
import json
import sys

domain, result, status, pid, started_at = sys.argv[1:]
print(json.dumps({
    "domain": domain,
    "curl_exit": int(result),
    "http_status": status,
    "pid": int(pid),
    "started_at": started_at,
}))
PY

  if [[ "$mode" == block && "$domain" == example.com ]]; then
    case "$result" in
      6|7|28) ;;
      *) echo "::error::Expected transport denial for example.com, got curl exit $result."; exit 1 ;;
    esac
  elif [[ "$result" != 0 || ! "$http_status" =~ ^2[0-9][0-9]$ ]]; then
    echo "::error::Expected successful HTTPS request to $domain."
    exit 1
  fi
done
