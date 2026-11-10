"""Verify independent native evidence for the isolated coexistence pilot."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def verify_build(root, mode):
    build = json.loads((root / "build.json").read_text())
    for stage in ("install", "lint", "typecheck", "test", "build", "smoke"):
        if build.get(stage) != "success":
            raise ValueError(f"Legitimate build did not complete {stage}")
    hook = json.loads((root / "hook.json").read_text())
    if hook.get("domain") != "example.com":
        raise ValueError("Missing controlled dependency-hook identity")
    if mode == "audit":
        if hook.get("exit_code") != 0 or hook.get("http_status") != 200:
            raise ValueError("Unprotected controlled hook did not succeed")
    elif hook.get("exit_code") != 1 or not hook.get("error_code"):
        raise ValueError("Protected controlled hook was not rejected")
    return {"build": build, "hook": hook}


def marker_event(events, pid):
    for line in events.splitlines():
        event = json.loads(line)
        if event.get("rule") == "SS Pilot Controlled Process Marker":
            fields = event.get("output_fields", {})
            if str(fields.get("proc.pid")) == str(pid):
                return event
    return None


def verify_falco(root, wait_seconds=15):
    record = json.loads((Path(os.environ["RUNNER_TEMP"]) / "ss-pilot-falco-owner.json").read_text())
    container_id = record["id"]
    running = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
        capture_output=True, text=True, timeout=15, check=True,
    )
    if running.stdout.strip() != "true":
        raise ValueError("The owned Falco container is not running")
    pid = json.loads((root / "marker.json").read_text())["pid"]
    deadline = time.monotonic() + wait_seconds
    while True:
        result = subprocess.run(
            ["sudo", "cat", "/tmp/falco_events.json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            event = marker_event(result.stdout, pid)
            if event:
                (root / "falco-marker.json").write_text(json.dumps(event, indent=2) + "\n")
                return {"container_id": container_id, "marker_pid": pid, "rule": event["rule"]}
        if time.monotonic() >= deadline:
            raise ValueError("No matching Falco marker event found before deadline")
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--mode", choices=("audit", "block"), required=True)
    parser.add_argument("--detector", choices=("enabled", "disabled"), required=True)
    args = parser.parse_args()
    report = verify_build(args.directory, args.mode)
    if args.detector == "enabled":
        report["falco"] = verify_falco(args.directory)
    else:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=^/falco$", "--format", "{{.ID}}"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        if result.stdout.strip():
            raise ValueError("Unexpected Falco container in detector-disabled control")
        report["falco"] = "not started"
    (args.directory / "coexistence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
