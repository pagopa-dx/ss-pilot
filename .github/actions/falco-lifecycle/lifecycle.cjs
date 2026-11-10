const fs = require("node:fs");
const { execFileSync } = require("node:child_process");

function docker(args) {
  return execFileSync("docker", args, {
    encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function namedContainers(run = docker) {
  return run(["ps", "-a", "--filter", "name=^/falco$", "--format", "{{.ID}}"])
    .split("\n").filter(Boolean);
}

function findMarker(events, pid) {
  return events.split("\n").filter(Boolean).map((line) => JSON.parse(line)).find(
    (event) => event.rule === "SS Pilot Controlled Process Marker" &&
      String(event.output_fields?.["proc.pid"]) === String(pid),
  );
}

async function start(recordPath, ruleFile, run = docker) {
  if (!ruleFile || !pathIsSafe(ruleFile) || !fs.existsSync(ruleFile)) {
    throw new Error("Missing or invalid absolute Falco rule path");
  }
  run(["info", "--format", "{{.ServerVersion}}"]);
  if (namedContainers(run).length) throw new Error("A Falco container already exists; refusing to take ownership");
  if (fs.existsSync(recordPath)) throw new Error("Falco owner record already exists");
  if (fs.existsSync("/tmp/falco_events.json")) throw new Error("Falco event file already exists");
  const id = run([
    "create", "--name", "falco", "--privileged",
    "-v", "/tmp:/tmp",
    "-v", "/sys/kernel/tracing:/sys/kernel/tracing:ro",
    "-v", "/var/run/docker.sock:/host/var/run/docker.sock",
    "-v", "/proc:/host/proc:ro",
    "-v", "/etc:/host/etc:ro",
    "-v", `${ruleFile}:/etc/falco/rules.d/custom_rules.yaml:ro`,
    "falcosecurity/falco@sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e",
    "falco", "-o", "json_output=true", "-o", "file_output.enabled=true",
    "-o", "file_output.keep_alive=false", "-o", "file_output.filename=/tmp/falco_events.json",
    "-o", "engine.kind=modern_ebpf",
  ]);
  if (!/^[a-f0-9]{64}$/.test(id)) throw new Error("Invalid Falco container ID returned by Docker");
  fs.writeFileSync(recordPath, JSON.stringify({ id }), { flag: "wx" });
  run(["start", id]);

  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (run(["inspect", "--format", "{{.State.Running}}", id]) !== "true") {
      throw new Error(`Falco container exited during startup: ${run(["logs", id])}`);
    }
    if (fs.existsSync("/tmp/falco_events.json")) {
      const pid = execFileSync("python3", ["-c", "import os; print(os.getpid())", "ss-pilot-controlled-marker"], {
        encoding: "utf8", timeout: 10000,
      }).trim();
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const events = execFileSync("sudo", ["cat", "/tmp/falco_events.json"], { encoding: "utf8", timeout: 10000 });
      if (findMarker(events, pid)) return { id, marker_pid: pid };
    } else {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  throw new Error("Falco did not detect the startup marker before the deadline");
}

function pathIsSafe(value) {
  return require("node:path").isAbsolute(value) && !value.includes(":") && !value.includes("\n");
}

function cleanup(recordPath, run = docker, read = fs.readFileSync) {
  if (!fs.existsSync(recordPath)) {
    if (namedContainers(run).length) {
      throw new Error("Falco container exists without a recorded owner ID; refusing to stop it.");
    }
    return { status: "not-started" };
  }
  const record = JSON.parse(read(recordPath, "utf8"));
  if (!/^[a-f0-9]{64}$/.test(record.id)) throw new Error("Invalid Falco owner ID");
  const running = run(["inspect", "--format", "{{.State.Running}}", record.id]);
  if (running === "true") run(["stop", "--time", "10", record.id]);
  run(["rm", record.id]);
  if (running !== "true") throw new Error("Owned Falco container was not running at cleanup; removed it");
  return { status: "stopped", id: record.id };
}

module.exports = { cleanup, docker, findMarker, namedContainers, start };
