const fs = require("node:fs");
const path = require("node:path");
const { docker, namedContainers } = require("./lifecycle.cjs");

try {
  if (!process.env.RUNNER_TEMP || !process.env.GITHUB_STATE) {
    throw new Error("Missing GitHub runner lifecycle paths");
  }
  docker(["info", "--format", "{{.ServerVersion}}"]);
  if (namedContainers().length) throw new Error("A Falco container already exists; refusing to take ownership");
  const recordPath = path.join(process.env.RUNNER_TEMP, "ss-pilot-falco-owner.json");
  if (fs.existsSync(recordPath)) throw new Error("Falco owner record already exists");
  fs.appendFileSync(process.env.GITHUB_STATE, `falco_record=${recordPath}\n`);
  console.log("Falco post-job cleanup registered before startup.");
} catch (error) {
  console.error(`::error::Falco lifecycle registration failed: ${error.message}`);
  process.exitCode = 1;
}
