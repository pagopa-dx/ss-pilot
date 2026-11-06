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

pnpm --version | tee "$evidence_dir/pnpm-version.log"
node --version | tee "$evidence_dir/node-version.log"

# Keep the legitimate build separate from the one explicitly approved lifecycle probe.
pnpm install --frozen-lockfile --ignore-scripts --store-dir "${PILOT_PNPM_STORE:?Specify a fresh pnpm store}" \
  2>&1 | tee "$evidence_dir/install.log"
pnpm lint:check 2>&1 | tee "$evidence_dir/lint.log"
pnpm typecheck 2>&1 | tee "$evidence_dir/typecheck.log"
pnpm test 2>&1 | tee "$evidence_dir/test.log"
pnpm build 2>&1 | tee "$evidence_dir/build.log"
test -s dist/payment.js
node --input-type=module - <<'JS' | tee "$evidence_dir/smoke.log"
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
