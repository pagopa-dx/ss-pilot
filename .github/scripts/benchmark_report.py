import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
import statistics

from benchmark_evidence import classify, matches
from verify_runtime_evidence import read_jsonl


def load_results(root):
    results = []
    missing = []
    for folder in sorted(root.glob("benchmark-*")):
        result = folder / "result.json"
        if not result.exists():
            missing.append(folder.name)
            continue
        record = json.loads(result.read_text())
        record["artifact"] = folder.name
        record["_directory"] = folder
        results.append(record)
    return results, missing


def seconds(step):
    start, end = step.get("started_at"), step.get("completed_at")
    return (datetime.fromisoformat(end.replace("Z", "+00:00")) - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds() if start and end else None


def aggregate(root, jobs, profile):
    records, missing = load_results(root)
    baseline = defaultdict(list)
    for record in records:
        if record["tool"] == "baseline":
            for probe in record.get("probes", []):
                baseline[(probe["case"], record.get("image_version"))].append(probe.get("reached", False))
    cases, faults, performance = [], [], defaultdict(list)
    builds = []
    tier = []
    for record in records:
        tool, mode, kind = (record[key] for key in ("tool", "mode", "kind"))
        directory = record["_directory"]
        native = directory / ("agent.log" if tool == "stepsecurity" else "events.jsonl")
        events = native.read_text().splitlines() if tool == "stepsecurity" and native.exists() else read_jsonl(native) if tool != "baseline" and native.exists() else []
        if record.get("agent_build"):
            tier.extend(record["agent_build"])
        if record.get("phases"):
            builds.append({"tool": tool, "mode": mode, "kind": kind, "iteration": record["iteration"], "completed": record["completed"]})
        for probe in record.get("probes", []):
            proof = matches(tool, probe, events)
            controls = baseline.get((probe["case"], record.get("image_version")), [])
            status, reason = classify(tool, mode, probe, any(controls), proof)
            cases.append({
                "tool": tool, "mode": mode, "iteration": record["iteration"], "case": probe["case"],
                "status": status, "reason": reason, "reached": probe.get("reached"),
                "baseline_successes": sum(controls), "baseline_samples": len(controls),
                "native_evidence": proof[:8], "artifact": record["artifact"],
            })
        if kind == "performance":
            environment = (record.get("image_version"), record.get("kernel"), record.get("cpu_model"), record.get("cpu_count"))
            for cache, phase in record["phases"].items():
                resources = phase["resources"]
                performance[(tool, mode, cache, environment)].append({
                    "wall_seconds": sum(item["wall_seconds"] for item in resources.values()),
                    "user_seconds": sum(item["user_seconds"] for item in resources.values()),
                    "system_seconds": sum(item["system_seconds"] for item in resources.values()),
                    "max_command_rss_kb": max(item["max_rss_kb"] for item in resources.values()),
                    "install_seconds": resources["install"]["wall_seconds"],
                    "artifact": record["artifact"],
                })
        if kind in ("startup-failure", "agent-exit", "timeout", "cancellation"):
            if kind == "startup-failure":
                status = "passed" if record.get("startup_failed") and not record.get("workload_started") else "failed"
                reason = "Invalid startup must fail and must not start the application"
            elif kind == "agent-exit":
                fault = record["fault"]
                excluded = next(item for item in fault["probes"] if not item["allowed"])
                if excluded.get("reached"):
                    status, reason = "failed", "Excluded traffic reached its destination after guard termination"
                elif fault["guard_gate_rejected"]:
                    status, reason = "passed", "Application gate rejected the unavailable agent; residual packet enforcement is not proven"
                else:
                    status, reason = "inconclusive", "Agent may have recovered; inspect replacement PID and network evidence"
            elif kind == "timeout":
                status = "passed" if record.get("timeout_outcome") == "failure" and record.get("waiting_marker") and record.get("child_timeout", {}).get("status") == "timeout" else "inconclusive"
                reason = "Actual GitHub step deadline and bounded child timeout; inspect native post cleanup independently"
            else:
                status = "passed" if record.get("waiting_marker") and record.get("job_status") == "cancelled" else "inconclusive"
                reason = "Cancellation marker and GitHub cancellation state; inspect native post cleanup independently"
            faults.append({"tool": tool, "kind": kind, "status": status, "reason": reason, "artifact": record["artifact"]})
    measurements = []
    for (tool, mode, cache, environment), samples in sorted(performance.items(), key=lambda entry: str(entry[0])):
        metrics = {
            metric: {"median": statistics.median(sample[metric] for sample in samples), "min": min(sample[metric] for sample in samples), "max": max(sample[metric] for sample in samples)}
            for metric in ("wall_seconds", "user_seconds", "system_seconds", "max_command_rss_kb", "install_seconds")
        }
        measurements.append({"tool": tool, "mode": mode, "cache": cache, "environment": environment, "samples": len(samples), "metrics": metrics})
    for measurement in measurements:
        control = next((
            item for item in measurements
            if item["tool"] == "baseline" and item["cache"] == measurement["cache"]
            and item["environment"] == measurement["environment"]
        ), None)
        if control and measurement["tool"] != "baseline":
            reference = control["metrics"]["wall_seconds"]["median"]
            measurement["matched_baseline_samples"] = control["samples"]
            measurement["exploratory_wall_ratio"] = measurement["metrics"]["wall_seconds"]["median"] / reference if reference else None
    cleanup = []
    for job in jobs:
        if "Benchmark " not in job.get("name", ""):
            continue
        steps = job.get("steps", [])
        cleanup.append({
            "job": job["name"], "id": job["id"], "conclusion": job.get("conclusion"),
            "guard_setup_seconds": sum(seconds(step) or 0 for step in steps if "Start " in step.get("name", "")),
            "post_steps": [{"name": step["name"], "conclusion": step.get("conclusion")} for step in steps if step.get("name", "").startswith("Post ")],
        })
    sizes = (1, 1) if profile == "smoke" else (3, 10)
    expected_keys = set()
    if profile != "cancellation":
        for kind, size in zip(("functional", "performance"), sizes):
            for iteration in range(1, size + 1):
                expected_keys.add(("baseline", "audit", kind, iteration))
                for tool in ("field-cage", "cargowall", "stepsecurity"):
                    expected_keys.update((tool, mode, kind, iteration) for mode in ("audit", "block"))
        for tool in ("field-cage", "cargowall", "stepsecurity"):
            expected_keys.update((tool, "block", kind, 1) for kind in ("startup-failure", "agent-exit", "timeout"))
    else:
        expected_keys = {(tool, "block", "cancellation", 1) for tool in ("field-cage", "cargowall", "stepsecurity")}
    actual_keys = {(record["tool"], record["mode"], record["kind"], record["iteration"]) for record in records}
    coherent = len({(record.get("sha"), record.get("run_id"), record.get("attempt")) for record in records}) == 1
    expected = len(expected_keys)
    return {
        "profile": profile, "expected_case_jobs": expected, "result_artifacts": len(records),
        "missing_result_artifacts": missing,
        "missing_cases": sorted(expected_keys - actual_keys),
        "unexpected_cases": sorted(actual_keys - expected_keys),
        "coverage_complete": actual_keys == expected_keys and len(records) == expected and coherent and not missing and all(record.get("completed") for record in records),
        "builds": builds, "cases": cases, "faults": faults,
        "case_status_counts": dict(Counter(case["status"] for case in cases)),
        "performance": measurements, "cleanup": cleanup,
        "stepsecurity_agent_builds": sorted(set(tier)),
        "community_only_test": "inconclusive: the pinned action exposes no supported input to force the Community agent; no organization license or App was changed",
        "limits": [
            "HTTP 403 is transport reachability, not a firewall denial.",
            "Each performance job has a fresh runner; cold install precedes a warm-store offline reinstall.",
            "Statistics are stratified by image, kernel, CPU model and vCPU count; small strata are not a ranking.",
            "Maximum command RSS is not total concurrent job/container memory.",
            "Artifact capture precedes native post steps; BENCHMARK_OBSERVER_FINAL in job logs covers the later window.",
            "No TLS payload decryption, all-destination vendor identification, Azure export or Container Apps compatibility claim.",
        ],
    }


def markdown(report):
    lines = [
        "# Runtime benchmark results", "",
        f"Profile: **{report['profile']}**. Collected {report['result_artifacts']}/{report['expected_case_jobs']} expected result artifacts.",
        f"Coverage complete: **{report['coverage_complete']}**. Harness success is not a blanket security pass.", "",
        "## Functional cases", "",
        "| Tool | Mode | Case | Passed | Failed | Unsupported | Inconclusive |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    grouped = defaultdict(Counter)
    for case in report["cases"]:
        grouped[(case["tool"], case["mode"], case["case"])][case["status"]] += 1
    for (tool, mode, case), counts in sorted(grouped.items()):
        lines.append(f"| {tool} | {mode} | {case} | " + " | ".join(str(counts[key]) for key in ("passed", "failed", "unsupported", "inconclusive")) + " |")
    lines.extend(["", "## Fault cases", "", "| Tool | Fault | Status | Meaning |", "| --- | --- | --- | --- |"])
    for fault in report["faults"]:
        lines.append(f"| {fault['tool']} | {fault['kind']} | {fault['status']} | {fault['reason']} |")
    lines.extend(["", "## Performance by matched environment", "", "| Tool | Mode | Cache | Samples | Median build seconds | Median install seconds | Image / CPU |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for sample in report["performance"]:
        lines.append(f"| {sample['tool']} | {sample['mode']} | {sample['cache']} | {sample['samples']} | {sample['metrics']['wall_seconds']['median']:.2f} | {sample['metrics']['install_seconds']['median']:.2f} | {sample['environment'][0]} / {sample['environment'][2]} |")
    lines.extend(["", "## Tier and interpretation", "", report["community_only_test"], ""])
    lines.extend(report["stepsecurity_agent_builds"])
    lines.extend(["", *["- " + item for item in report["limits"]], ""])
    if report["missing_result_artifacts"]:
        lines.extend(["## Missing/incomplete results", "", *["- " + item for item in report["missing_result_artifacts"]]])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--profile", choices=("full", "smoke", "cancellation"), required=True)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    jobs = json.loads(args.jobs.read_text()) if args.jobs else []
    report = aggregate(args.directory, jobs, args.profile)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output / "report.md").write_text(markdown(report))
    print(json.dumps({key: report[key] for key in ("coverage_complete", "result_artifacts", "expected_case_jobs", "case_status_counts", "missing_result_artifacts")}, indent=2))


if __name__ == "__main__":
    main()
