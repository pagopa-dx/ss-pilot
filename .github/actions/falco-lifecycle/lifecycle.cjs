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
  if (running !== "true") throw new Error("Owned Falco container was not running at cleanup");
  run(["stop", "--time", "10", record.id]);
  return { status: "stopped", id: record.id };
}

module.exports = { cleanup, docker, namedContainers };
