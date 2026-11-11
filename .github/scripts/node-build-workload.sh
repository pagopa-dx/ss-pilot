#!/usr/bin/env bash
set -euo pipefail

mode="${1:?Specify audit or block}"
evidence_dir="${2:?Specify an absolute evidence directory}"
case "$mode" in
  audit|block) ;;
  *) echo "::error::Unsupported build mode: $mode"; exit 1 ;;
esac
if [[ "$evidence_dir" != /* ]]; then
  echo "::error::The build evidence directory must be absolute."
  exit 1
fi
mkdir -p "$evidence_dir"
cd fixtures/node-build

run_stage() {
  local stage="$1"
  shift
  if [[ "${BENCHMARK_MEASURE:-false}" == true ]]; then
    /usr/bin/time --quiet \
      -f '{"wall_seconds":%e,"user_seconds":%U,"system_seconds":%S,"max_rss_kb":%M}' \
      -o "$evidence_dir/$stage.resources.json" "$@" 2>&1 | tee "$evidence_dir/$stage.log"
  else
    "$@" 2>&1 | tee "$evidence_dir/$stage.log"
  fi
}

pnpm --version | tee "$evidence_dir/pnpm-version.log"
node --version | tee "$evidence_dir/node-version.log"

# Keep the legitimate build separate from the one explicitly approved lifecycle probe.
install_args=(install --frozen-lockfile --ignore-scripts --store-dir "${PILOT_PNPM_STORE:?Specify a fresh pnpm store}")
if [[ "${PILOT_OFFLINE_INSTALL:-false}" == true ]]; then
  install_args+=(--offline --force)
fi
run_stage install pnpm "${install_args[@]}"
run_stage lint pnpm lint:check
run_stage typecheck pnpm typecheck
run_stage test pnpm test
run_stage build pnpm build
test -s dist/payment.js
run_stage smoke node --input-type=module - <<'JS'
import assert from "node:assert/strict";
import { summarizePayments } from "./dist/payment.js";
assert.deepEqual(
  summarizePayments([{ amountCents: 1250, reference: "synthetic-only" }]),
  { count: 1, totalCents: 1250 },
);
console.log("Compiled application smoke test passed.");
JS
printf '%s\n' '{"install":"success","lint":"success","typecheck":"success","test":"success","build":"success","smoke":"success"}' \
  > "$evidence_dir/build.json"

export PILOT_HOOK_RESULT="$evidence_dir/hook.json"
if pnpm --dir node_modules/pilot-install-hook run postinstall 2>&1 | tee "$evidence_dir/hook.log"; then
  result=0
else
  result=$?
fi
python3 - "$result" "$evidence_dir/lifecycle-command.json" <<'PY'
import json
from pathlib import Path
import sys

Path(sys.argv[2]).write_text(json.dumps({"exit_code": int(sys.argv[1])}) + "\n")
PY
if [[ "${BENCHMARK_OBSERVE_ONLY:-false}" == true ]]; then
  echo "Benchmark observed lifecycle exit $result; acceptance is deferred to the cross-job report."
  exit 0
fi
python3 - "$mode" "$PILOT_HOOK_RESULT" "$result" <<'PY'
import json
from pathlib import Path
import sys

mode, path, result = sys.argv[1:]
record = json.loads(Path(path).read_text())
if mode == "audit":
    if int(result) != 0 or record.get("exit_code") != 0 or record.get("http_status") != 200:
        raise SystemExit("::error::The audit dependency hook did not reach example.com.")
else:
    expected = {"EACCES", "EPERM", "ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED",
                "ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT"}
    if int(result) == 0 or record.get("exit_code") != 1 or record.get("error_code") not in expected:
        raise SystemExit("::error::The dependency hook did not fail with an expected network denial.")
print(f"Controlled lifecycle command exited {result}; agent denial evidence is still required.")
PY
