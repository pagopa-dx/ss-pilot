const fs = require("node:fs");
const path = require("node:path");
const { start } = require("./lifecycle.cjs");

async function main() {
  if (!process.env.RUNNER_TEMP || !process.env.GITHUB_STATE) {
    throw new Error("Missing GitHub runner lifecycle paths");
  }
  const recordPath = path.join(process.env.RUNNER_TEMP, "ss-pilot-falco-owner.json");
  fs.appendFileSync(process.env.GITHUB_STATE, `falco_record=${recordPath}\n`);
  console.log("Falco post-job cleanup registered before startup.");
  const result = await start(recordPath, process.env["INPUT_RULE-FILE"]);
  console.log(`PILOT_FALCO_READY ${JSON.stringify(result)}`);
}

main().catch((error) => {
  console.error(`::error::Falco lifecycle registration failed: ${error.message}`);
  process.exitCode = 1;
});
