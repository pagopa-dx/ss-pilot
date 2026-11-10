const { cleanup } = require("./lifecycle.cjs");

try {
  if (!process.env.STATE_falco_record) throw new Error("Missing Falco lifecycle state");
  const outcome = cleanup(process.env.STATE_falco_record);
  console.log(`PILOT_FALCO_POST ${JSON.stringify(outcome)}`);
} catch (error) {
  console.error(`::error::Falco post-job cleanup failed: ${error.message}`);
  process.exitCode = 1;
}
