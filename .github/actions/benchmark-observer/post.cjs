const fs = require("node:fs");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");

async function main() {
  const pid = Number(process.env.STATE_observer_pid);
  const root = process.env.STATE_observer_root;
  if (!Number.isSafeInteger(pid) || pid <= 1 || !root) throw new Error("Missing observer identity");
  const cleanup = [];
  if (process.env.BENCHMARK_PROFILE === "gaps") {
    for (const host of ["example.org", "example.com"]) {
      for (const command of [
        ["getent", "ahostsv4", host],
        ["curl", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "3",
          "--max-time", "5", "--output", "/dev/null", "--write-out",
          '{"http_code":%{http_code},"remote_ip":"%{remote_ip}","remote_port":%{remote_port}}', `https://${host}/`],
      ]) {
        const started = Date.now();
        const result = spawnSync(command[0], command.slice(1), { encoding: "utf8", timeout: 8000 });
        cleanup.push({ command, pid: result.pid, started_at: started, finished_at: Date.now(),
          exit_code: result.status, error: result.error?.message, signal: result.signal,
          stdout: result.stdout?.slice(0, 16000), stderr: result.stderr?.slice(0, 2000),
          truncated: result.stdout?.length > 16000 });
      }
    }
    console.log("BENCHMARK_CLEANUP_CONNECTIVITY " + JSON.stringify(cleanup));
  }
  const file = path.join(root, "observer-final.json");
  if (!fs.existsSync(file)) process.kill(pid, "SIGTERM");
  for (let i = 0; i < 100 && !fs.existsSync(file); i++) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!fs.existsSync(file)) throw new Error("Observer did not finish during post cleanup");
  const final = JSON.parse(fs.readFileSync(file, "utf8"));
  const network = fs.readFileSync(path.join(root, "network.log"), "utf8");
  const vendorNames = [...new Set(network.match(/\b[\w.-]*(?:stepsecurity\.io|codecargo\.com)\.?/gi) || [])];
  const destinations = [...new Set(network.split("\n").flatMap((line) => {
    const match = line.match(/\bIP6? \S+ > (\S+):/);
    return match ? [match[1]] : [];
  }))];
  const processes = execFileSync("ps", ["-eo", "pid,ppid,comm"], { encoding: "utf8" });
  console.log("BENCHMARK_OBSERVER_FINAL " + JSON.stringify({
    ...final, vendor_dns_names: vendorNames, process_snapshot: processes,
    cleanup_connectivity: cleanup,
    destination_endpoints: destinations.slice(0, 2000),
    destination_list_truncated: destinations.length > 2000,
    artifact_window: "The uploaded snapshot precedes native post steps; this final record is retained in the job log.",
  }));
  if (final.errors.length) throw new Error(`Observer incomplete: ${final.errors.join("; ")}`);
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
