#!/usr/bin/env bash
set -euo pipefail

tool="${1:?Specify a tool}"
evidence_dir="${2:?Specify an evidence directory}"
mkdir -p "$evidence_dir"
sleep 2
case "$tool" in
  field-cage)
    if [[ -n "${FC_BIN:-}" && -f "$evidence_dir/agent.log" ]]; then
      "$FC_BIN" report --log "$evidence_dir/agent.log" --raw --format json > "$evidence_dir/events.jsonl"
    else
      echo "::warning::field-cage native logs are unavailable."
    fi
    ;;
  cargowall)
    if sudo test -f /tmp/cargowall-audit.json; then
      sudo cat /tmp/cargowall-audit.json > "$evidence_dir/events.jsonl"
    else
      echo "::warning::CargoWall native events are unavailable."
    fi
    if sudo test -f /tmp/cargowall.log; then
      sudo cat /tmp/cargowall.log > "$evidence_dir/agent.log"
    else
      echo "::warning::CargoWall startup diagnostics are unavailable."
    fi
    ;;
  stepsecurity)
    if sudo test -f /home/agent/agent.log; then
      sudo cat /home/agent/agent.log > "$evidence_dir/agent.log"
    else
      echo "::warning::StepSecurity native logs are unavailable."
    fi
    ;;
  *)
    echo "::error::Unsupported security tool: $tool"
    exit 1
    ;;
esac
