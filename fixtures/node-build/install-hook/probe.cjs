const { writeFileSync } = require("node:fs");
const https = require("node:https");

const resultPath = process.env.PILOT_HOOK_RESULT;
if (!resultPath) {
  console.error("This controlled install hook requires PILOT_HOOK_RESULT.");
  process.exit(1);
}

let completed = false;
function finish(result) {
  if (completed) return;
  completed = true;
  clearTimeout(deadline);
  const record = {
    domain: "example.com",
    pid: process.pid,
    observed_at: new Date().toISOString(),
    ...result,
  };
  writeFileSync(resultPath, JSON.stringify(record) + "\n");
  console.log("Controlled dependency postinstall:", JSON.stringify(record));
  process.exitCode = result.exit_code;
}

const request = https.get("https://example.com/", (response) => {
  response.resume();
  response.on("error", (error) => {
    finish({ exit_code: 1, error_code: error.code || "RESPONSE_ERROR" });
  });
  response.on("end", () => {
    const status = response.statusCode;
    finish({
      exit_code: status >= 200 && status < 300 ? 0 : 1,
      http_status: status,
    });
  });
});
request.on("error", (error) => {
  finish({ exit_code: 1, error_code: error.code || "REQUEST_ERROR" });
});
const deadline = setTimeout(() => {
  const error = new Error("Controlled request exceeded 15 seconds");
  error.code = "ETIMEDOUT";
  request.destroy(error);
}, 15000);
