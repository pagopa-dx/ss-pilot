const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { cleanup, findMarker } = require("../actions/falco-lifecycle/lifecycle.cjs");

test("stops exactly the recorded running container", () => {
  const id = "a".repeat(64);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "falco-lifecycle-")), "owner.json");
  fs.writeFileSync(file, JSON.stringify({ id }));
  const calls = [];
  const run = (args) => {
    calls.push(args);
    return args[0] === "inspect" ? "true" : id;
  };
  try {
    assert.deepEqual(cleanup(file, run), { status: "stopped", id });
    assert.deepEqual(calls, [
      ["inspect", "--format", "{{.State.Running}}", id],
      ["stop", "--time", "10", id],
      ["rm", id],
    ]);
  } finally {
    fs.unlinkSync(file);
    fs.rmdirSync(path.dirname(file));
  }
});

test("startup marker requires the same rule and process and rejects malformed events", () => {
  const events = [
    { rule: "other", output_fields: { "proc.pid": 101 } },
    { rule: "SS Pilot Controlled Process Marker", output_fields: { "proc.pid": 102 } },
  ].map(JSON.stringify).join("\n");
  assert.equal(findMarker(events, 101), undefined);
  assert.equal(findMarker(events, 102).rule, "SS Pilot Controlled Process Marker");
  assert.throws(() => findMarker("not-json", 101), SyntaxError);
});

test("refuses an unowned or invalid container and surfaces dead-agent errors", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "falco-lifecycle-"));
  const file = path.join(dir, "owner.json");
  try {
    assert.deepEqual(cleanup(file, () => ""), { status: "not-started" });
    assert.throws(() => cleanup(file, () => "123"), /without a recorded owner/);
    fs.writeFileSync(file, JSON.stringify({ id: "invalid" }));
    assert.throws(() => cleanup(file, () => "true"), /Invalid Falco owner ID/);
    fs.writeFileSync(file, JSON.stringify({ id: "b".repeat(64) }));
    assert.throws(() => cleanup(file, () => "false"), /not running/);
    assert.throws(() => cleanup(file, () => { throw new Error("Docker failed"); }), /Docker failed/);
  } finally {
    fs.unlinkSync(file);
    fs.rmdirSync(dir);
  }
});
