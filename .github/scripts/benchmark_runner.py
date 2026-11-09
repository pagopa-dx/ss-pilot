import argparse
import json
import os
from pathlib import Path
import platform
import random
import subprocess
import sys
import time

from benchmark_probes import curl_probe, probes
from verify_node_build import verify
from verify_runtime_evidence import read_jsonl


ROOT = Path(os.environ.get("PILOT_DIR", "/tmp/runtime-benchmark"))


def save(name, value):
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n")


def identity():
    cpu_info = Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").is_file() else ""
    model = next((line.split(":", 1)[1].strip() for line in cpu_info.splitlines() if line.startswith("model name")), None)
    return {
        "tool": os.environ["BENCHMARK_TOOL"],
        "mode": os.environ["BENCHMARK_MODE"],
        "kind": os.environ["BENCHMARK_KIND"],
        "iteration": int(os.environ["BENCHMARK_ITERATION"]),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "sha": os.environ.get("GITHUB_SHA"),
        "image_version": os.environ.get("ImageVersion"),
        "image_os": os.environ.get("ImageOS"),
        "kernel": platform.release(),
        "cpu_count": os.cpu_count(),
        "cpu_model": model,
    }


def guard_pid(tool):
    if tool == "baseline":
        return None
    if tool == "stepsecurity":
        result = subprocess.run(
            ["systemctl", "show", "agent.service", "--property=MainPID", "--value"],
            text=True, capture_output=True, check=True, timeout=5,
        )
        value = result.stdout.strip()
    else:
        value = os.environ.get("FC_PID" if tool == "field-cage" else "BENCHMARK_GUARD_PID", "")
    if not value.isdigit() or int(value) <= 1:
        raise ValueError(f"{tool} did not expose a valid guard PID")
    pid = int(value)
    result = subprocess.run(["sudo", "kill", "-0", str(pid)], capture_output=True, timeout=5)
    if result.returncode:
        raise ValueError(f"{tool} guard PID {pid} is not alive")
    executable = subprocess.run(
        ["sudo", "readlink", f"/proc/{pid}/exe"], capture_output=True, text=True, check=True, timeout=5,
    ).stdout.strip()
    expected = {"stepsecurity": "agent", "field-cage": "field-cage", "cargowall": "cargowall"}[tool]
    if expected not in Path(executable).name:
        raise ValueError(f"Guard PID resolves to unexpected executable: {executable}")
    if tool == "cargowall" and not Path("/tmp/cargowall-ready").is_file():
        raise ValueError("CargoWall readiness marker missing")
    return pid


def plan(profile):
    count = 1 if profile == "smoke" else 3
    samples = 1 if profile == "smoke" else 10
    baseline = [
        {"kind": kind, "iteration": index, "mode": "audit"}
        for kind, size in (("functional", count), ("performance", samples))
        for index in range(1, size + 1)
    ]
    guards = [{**case, "mode": mode} for case in baseline for mode in ("audit", "block")]
    guards.extend({"kind": kind, "iteration": 1, "mode": "block"} for kind in ("startup-failure", "agent-exit", "timeout"))
    if profile == "cancellation":
        guards = [{"kind": "cancellation", "iteration": 1, "mode": "block"}]
    seed = os.environ.get("GITHUB_SHA", "local")
    rng = random.Random(seed)
    rng.shuffle(baseline)
    rng.shuffle(guards)
    output = {"baseline": {"include": baseline}, "guards": {"include": guards}}
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in output.items():
            stream.write(f"{key}={json.dumps(value, separators=(',', ':'))}\n")
    print(json.dumps({"profile": profile, "seed": seed, "baseline_jobs": len(baseline), "guard_jobs_per_tool": len(guards)}))


def build(mode, cache):
    directory = ROOT / cache
    directory.mkdir(exist_ok=True)
    env = {**os.environ, "BENCHMARK_MEASURE": "true", "CI": "true"}
    if cache == "warm":
        env["PILOT_OFFLINE_INSTALL"] = "true"
    started = time.time()
    result = subprocess.run(
        ["bash", ".github/scripts/node-build-workload.sh", mode, str(directory)],
        env=env, timeout=240, check=False,
    )
    save(f"{cache}/command.json", {"exit_code": result.returncode, "started_at": started, "finished_at": time.time()})
    if result.returncode:
        raise ValueError(f"{cache} legitimate-build/lifecycle control failed: exit {result.returncode}")


def run():
    context = identity()
    context["guard_pid"] = guard_pid(context["tool"])
    context["started_at"] = time.time()
    save("context.json", context)
    save("workload-started.json", {"at": time.time()})
    build(context["mode"], "cold")
    if context["kind"] == "performance":
        build(context["mode"], "warm")
    elif context["kind"] == "functional":
        probes(ROOT)
    else:
        raise ValueError("Unexpected workload kind")
    guard_pid(context["tool"])
    save("workload-finished.json", {"at": time.time()})


def fault():
    context = identity()
    pid = guard_pid(context["tool"])
    save("context.json", {**context, "guard_pid": pid})
    if context["kind"] != "agent-exit":
        raise ValueError("Unsupported shell-injected fault")
    at = time.time()
    result = subprocess.run(["sudo", "kill", "-KILL", str(pid)], capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise ValueError(f"Fault injection failed: {result.stderr}")
    time.sleep(2)
    try:
        replacement = guard_pid(context["tool"])
        rejected = False
    except ValueError as error:
        replacement = None
        rejected = True
        print(f"Guard gate rejected the unavailable agent: {error}")
    outcomes = [
        curl_probe("after-exit-allowed", "https://example.org/", [], True),
        curl_probe("after-exit-excluded", "https://example.com/", [], False),
    ]
    save("fault.json", {
        "kind": "agent-exit", "at": at, "original_pid": pid,
        "guard_gate_rejected": rejected, "replacement_pid": replacement,
        "workload_started": False, "probes": outcomes,
        "limits": "Diagnostic probes intentionally run after the gate rejects the guard; the application workload does not.",
    })


def finalize():
    context = identity()
    root = ROOT
    native = root / ("agent.log" if context["tool"] == "stepsecurity" else "events.jsonl")
    if context["tool"] == "baseline":
        events = []
    elif context["kind"] == "startup-failure" and not native.exists():
        print("::warning::No native events are available after the deliberately failed guard startup.")
        events = []
    else:
        events = native.read_text().splitlines() if context["tool"] == "stepsecurity" else read_jsonl(native)
    report = {**context, "guard_outcome": os.environ.get("BENCHMARK_GUARD_OUTCOME"), "job_status": os.environ.get("BENCHMARK_JOB_STATUS")}
    if context["kind"] in ("functional", "performance"):
        report["phases"] = {}
        for cache in ("cold", "warm") if context["kind"] == "performance" else ("cold",):
            folder = root / cache
            legitimate = json.loads((folder / "build.json").read_text())
            hook = json.loads((folder / "hook.json").read_text())
            lifecycle = json.loads((folder / "lifecycle-command.json").read_text())
            if context["tool"] == "baseline":
                if set(legitimate.values()) != {"success"} or hook.get("http_status") != 200 or lifecycle.get("exit_code") != 0:
                    raise ValueError("Invalid unprotected build control")
            else:
                verify(context["tool"], context["mode"], legitimate, hook, lifecycle, events, (root / "network.log").read_text())
            report["phases"][cache] = {
                "build": legitimate, "hook": hook,
                "resources": {stage: json.loads((folder / f"{stage}.resources.json").read_text()) for stage in legitimate},
            }
        if context["kind"] == "functional":
            report["probes"] = json.loads((root / "probes.json").read_text())
        report["completed"] = (root / "workload-finished.json").is_file()
    elif context["kind"] == "startup-failure":
        report["completed"] = True
        report["startup_failed"] = report["guard_outcome"] == "failure"
        report["workload_started"] = (root / "workload-started.json").exists()
    elif context["kind"] == "agent-exit":
        report["fault"] = json.loads((root / "fault.json").read_text())
        report["completed"] = True
    elif context["kind"] in ("timeout", "cancellation"):
        report["timeout_outcome"] = os.environ.get("BENCHMARK_TIMEOUT_OUTCOME")
        report["waiting_marker"] = (root / "fault-waiting.json").exists()
        report["completed"] = True
        if (root / "timeout.json").exists():
            report["child_timeout"] = json.loads((root / "timeout.json").read_text())
    else:
        raise ValueError("Unknown benchmark kind")
    if context["tool"] == "stepsecurity":
        lines = [line for line in events if "[buildInfo]" in line]
        report["agent_build"] = lines[:1]
        report["community_only"] = False if any("AgentAlpha" in line for line in lines) else None
    report["native_events"] = len(events)
    save("result.json", report)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
        stream.write(
            f"\n## Benchmark collected: {context['tool']} {context['mode']} {context['kind']}\n\n"
            "This job status describes harness completion, not a blanket security pass. "
            "The cross-job report uses matching unprotected controls and native evidence.\n"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("plan", "run", "fault", "finalize", "gate", "wait"))
    parser.add_argument("--profile", default="full", choices=("full", "smoke", "cancellation"))
    args = parser.parse_args()
    if args.operation == "plan":
        plan(args.profile)
    elif args.operation == "run":
        run()
    elif args.operation == "fault":
        fault()
    elif args.operation == "finalize":
        finalize()
    elif args.operation == "gate":
        print(f"Active guard verified: {guard_pid(os.environ['BENCHMARK_TOOL'])}")
    else:
        pid = guard_pid(os.environ["BENCHMARK_TOOL"])
        save("fault-waiting.json", {"at": time.time(), "guard_pid": pid})
        print("BENCHMARK_CANCELLATION_READY", flush=True)
        time.sleep(300)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        save("harness-error.json", {"error": str(error), "at": time.time()})
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
