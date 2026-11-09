const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

async function main() {
  const root = process.env.PILOT_DIR;
  if (!root || !path.isAbsolute(root)) throw new Error("PILOT_DIR must be absolute");
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const fd = fs.openSync(path.join(root, "observer.stderr"), "a", 0o600);
  const child = spawn(process.execPath, [path.join(__dirname, "observe.cjs"), root], {
    detached: true,
    stdio: ["ignore", fd, fd],
  });
  child.unref();
  fs.closeSync(fd);
  fs.appendFileSync(process.env.GITHUB_STATE, `observer_pid=${child.pid}\nobserver_root=${root}\n`);
  const ready = path.join(root, "observer-ready.json");
  for (let i = 0; i < 100; i++) {
    if (fs.existsSync(ready)) {
      console.log(`Independent observer started before guard setup: PID ${child.pid}`);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Observer startup failed: ${fs.readFileSync(path.join(root, "observer.stderr"), "utf8")}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
