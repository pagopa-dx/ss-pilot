const fs = require("node:fs");
const path = require("node:path");
const dns = require("node:dns").promises;
const { spawn, execFile } = require("node:child_process");
const root = process.argv[2];
const startedAt = new Date().toISOString();
let stopping = false;
let socketBusy = false;
let packetBytes = 0;
const errors = [];
const packets = fs.createWriteStream(path.join(root, "network.log"), { mode: 0o600 });
const packetErrors = fs.createWriteStream(path.join(root, "capture.stderr"), { mode: 0o600 });
const capture = spawn("sudo", [
  "tcpdump", "--immediate-mode", "-i", "any", "-nn", "-tt", "-l", "-s", "256",
  "tcp or udp",
], { stdio: ["ignore", "pipe", "pipe"] });
capture.stdout.on("data", (chunk) => {
  packetBytes += chunk.length;
  if (packetBytes <= 20 * 1024 * 1024) packets.write(chunk);
  else if (!errors.includes("packet-log-size-limit")) errors.push("packet-log-size-limit");
});
capture.stderr.pipe(packetErrors);
capture.on("error", (error) => errors.push(`tcpdump: ${error.message}`));
capture.on("exit", (code, signal) => {
  if (!stopping) errors.push(`tcpdump exited unexpectedly: ${code}/${signal}`);
});

function sockets() {
  if (socketBusy || stopping) return;
  socketBusy = true;
  execFile("ss", ["-H", "-ntup"], { timeout: 2000, maxBuffer: 1024 * 1024 }, (error, stdout) => {
    socketBusy = false;
    if (error) errors.push(`ss: ${error.message}`);
    else fs.appendFileSync(path.join(root, "sockets.jsonl"), JSON.stringify({
      at: new Date().toISOString(), sockets: stdout,
    }) + "\n", { mode: 0o600 });
  });
}
const timer = setInterval(sockets, 1000);
sockets();

async function ready() {
  await new Promise((resolve) => setTimeout(resolve, 700));
  if (capture.exitCode !== null || errors.length) throw new Error("tcpdump did not remain active");
  const resolutions = {};
  for (const host of ["example.com", "example.org", "www.example.org"]) {
    try { resolutions[host] = await dns.lookup(host, { all: true }); }
    catch (error) { resolutions[host] = { error: error.code || error.message }; }
  }
  fs.writeFileSync(path.join(root, "pre-resolved.json"), JSON.stringify(resolutions, null, 2));
  fs.writeFileSync(path.join(root, "observer-ready.json"), JSON.stringify({
    pid: process.pid, capture_pid: capture.pid, started_at: startedAt,
  }));
}

async function stop() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  await new Promise((resolve) => execFile(
    "sudo", ["kill", "-INT", String(capture.pid)], { timeout: 3000 },
    (error) => { if (error) errors.push(`capture stop: ${error.message}`); resolve(); },
  ));
  for (let i = 0; i < 50 && capture.exitCode === null && capture.signalCode === null; i++) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (capture.exitCode === null && capture.signalCode === null) {
    errors.push("capture-stop-timeout");
    await new Promise((resolve) => execFile("sudo", ["kill", "-TERM", String(capture.pid)], () => resolve()));
  }
  packets.end();
  packetErrors.end();
  fs.writeFileSync(path.join(root, "observer-final.json"), JSON.stringify({
    started_at: startedAt, stopped_at: new Date().toISOString(),
    packet_text_bytes: packetBytes, errors,
    limits: "Starts before guard setup, not before runner boot or action download. " +
      "Socket process attribution is sampled; no TLS decryption or zero-egress guarantee.",
  }, null, 2));
  process.exit(errors.length ? 1 : 0);
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
ready().catch((error) => { errors.push(error.message); console.error(error); stop(); });
