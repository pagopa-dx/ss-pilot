const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

async function main() {
  const pid = Number(process.env.STATE_observer_pid);
  const root = process.env.STATE_observer_root;
  if (!Number.isSafeInteger(pid) || pid <= 1 || !root) throw new Error("Missing observer identity");
  const file = path.join(root, "observer-final.json");
  if (!fs.existsSync(file)) process.kill(pid, "SIGTERM");
  for (let i = 0; i < 100 && !fs.existsSync(file); i++) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!fs.existsSync(file)) throw new Error("Observer did not finish during post cleanup");
  const final = JSON.parse(fs.readFileSync(file, "utf8"));
  const network = fs.readFileSync(path.join(root, "network.log"), "utf8");
  const vendorNames = [...new Set(network.match(/\b[\w.-]*(?:stepsecurity\.io|codecargo\.com)\.?/gi) || [])];
  const processes = execFileSync("ps", ["-eo", "pid,ppid,comm"], { encoding: "utf8" });
  console.log("BENCHMARK_OBSERVER_FINAL " + JSON.stringify({
    ...final, vendor_dns_names: vendorNames, process_snapshot: processes,
    artifact_window: "The uploaded snapshot precedes native post steps; this final record is retained in the job log.",
  }));
  if (final.errors.length) throw new Error(`Observer incomplete: ${final.errors.join("; ")}`);
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
