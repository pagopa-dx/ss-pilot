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
    supervision_path = root / "completion-supervision.json"
    supervision = json.loads(supervision_path.read_text()) if supervision_path.exists() else {}
    supervised_ids = {job["id"] for job in supervision.get("unfinished", [])}
    reporting_failures = [
        {"id": job["id"], "job": job["name"], "reason": "Native post steps and Complete job finished, but the runner did not report job completion"}
        for job in jobs
        if job["id"] in supervised_ids or (
            job.get("status") != "completed" and any(
                step["name"] == "Complete job" and step["status"] == "completed"
                for step in job.get("steps", [])
            )
        )
    ]
    baseline = defaultdict(list)
    for record in records:
        if record["tool"] == "baseline":
            for probe in record.get("probes", []):
                baseline[(probe["case"], record.get("image_version"), record["kind"])].append(probe.get("reached", False))
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
            builds.append({
                "tool": tool, "mode": mode, "kind": kind, "iteration": record["iteration"],
                "completed": record["completed"],
                "phases": {cache: {key: phase.get(key) for key in ("build_status", "strict_lifecycle_verification", "strict_lifecycle_reason")} for cache, phase in record["phases"].items()},
            })
        for probe in record.get("probes", []):
            proof = matches(tool, probe, events)
            control_kind = "gap-allowed-first" if kind == "privacy" else kind
            controls = baseline.get((probe["case"], record.get("image_version"), control_kind), [])
            status, reason = classify(tool, mode, probe, any(controls), proof)
            cases.append({
                "tool": tool, "mode": mode, "iteration": record["iteration"], "case": probe["case"],
                "kind": kind, "telemetry_disabled": record.get("telemetry_disabled"),
                "status": status, "reason": reason, "reached": probe.get("reached"),
                "baseline_successes": sum(controls), "baseline_samples": len(controls),
                "native_evidence": proof[:8], "artifact": record["artifact"],
            })
        if kind == "performance":
            environment = (record.get("image_version"), record.get("kernel"), record.get("cpu_model"), record.get("cpu_count"))
            for cache, phase in record["phases"].items():
                if phase.get("build_status") != "passed":
                    continue
                resources = phase["resources"]
                performance[(tool, mode, cache, environment)].append({
                    "wall_seconds": sum(item["wall_seconds"] for item in resources.values()),
                    "user_seconds": sum(item["user_seconds"] for item in resources.values()),
                    "system_seconds": sum(item["system_seconds"] for item in resources.values()),
                    "max_command_rss_kb": max(item["max_rss_kb"] for item in resources.values()),
                    "install_seconds": resources["install"]["wall_seconds"],
                    "artifact": record["artifact"],
                })
        if kind in ("startup-failure", "agent-exit", "agent-exit-during", "timeout", "cancellation"):
            if kind == "startup-failure":
                status = "passed" if record.get("startup_failed") and not record.get("workload_started") else "failed"
                reason = "Invalid startup must fail and must not start the application" if status == "passed" else "Invalid configuration was accepted; an actual startup failure was not induced"
            elif kind.startswith("agent-exit"):
                fault = record["fault"]
                excluded = next((item for item in fault.get("probes", []) if not item["allowed"]), {})
                if fault.get("injected") is False:
                    status, reason = "unsupported", f"Signal rejected; actual agent exit was not induced: {fault.get('signal_error', '')}"
                elif excluded.get("reached"):
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
            fault_result = {"tool": tool, "kind": kind, "status": status, "reason": reason, "artifact": record["artifact"]}
            if kind.startswith("agent-exit"):
                fault_result["application_gate"] = "unsupported" if fault.get("injected") is False else "passed" if fault["guard_gate_rejected"] else "failed"
                fault_result["residual_network_enforcement"] = "unsupported" if fault.get("injected") is False else "failed" if excluded.get("reached") else "inconclusive"
                suffix = f"Benchmark {tool} {mode} {kind} {record['iteration']}"
                reporting_failed = any(item["job"].endswith(suffix) for item in reporting_failures)
                fault_result["runner_reporting"] = "failed" if reporting_failed else "not observed failing"
                if reporting_failed:
                    fault_result.update(status="failed", reason="Application gate rejected the dead agent, but DNS-dependent uploads/job completion failed; residual packet enforcement is not proven")
                if fault.get("supervised_workload"):
                    child = fault["supervised_workload"]
                    fault_result["supervised_workload"] = child
                    fault_result["workflow_mitigation"] = "passed" if child["alive_when_agent_loss_detected"] and child["exit_code"] < 0 and child["seconds_after_injection"] < 5 and fault["guard_gate_rejected"] else "inconclusive"
            faults.append(fault_result)
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
        if "Benchmark " not in job.get("name", "") or job.get("conclusion") == "skipped":
            continue
        steps = job.get("steps", [])
        cleanup.append({
            "job": job["name"], "id": job["id"], "conclusion": job.get("conclusion"),
            "guard_setup_seconds": sum(seconds(step) or 0 for step in steps if step.get("name", "").startswith(("Pre Start ", "Start "))),
            "post_steps": [{"name": step["name"], "conclusion": step.get("conclusion")} for step in steps if step.get("name", "").startswith("Post ")],
            "explicit_cleanup_steps": [{"name": step["name"], "conclusion": step.get("conclusion")} for step in steps if step.get("name", "").startswith("Stop field-cage")],
        })
    sizes = (1, 1) if profile == "smoke" else (3, 10)
    expected_keys = set()
    if profile == "udp":
        expected_keys = {("baseline", "audit", "gap-udp", 1)}
        expected_keys.update((tool, "block", "gap-udp", 1) for tool in ("field-cage", "cargowall", "stepsecurity"))
    elif profile == "gaps":
        for kind in ("gap-excluded-first", "gap-allowed-first", "gap-pinned"):
            for i in range(1, 4):
                expected_keys.add(("baseline", "audit", kind, i))
                expected_keys.update((tool, "block", kind, i) for tool in ("field-cage", "cargowall", "stepsecurity"))
        for tool in ("field-cage", "cargowall"):
            expected_keys.update((tool, "block", kind, 1) for kind in ("agent-exit", "agent-exit-during"))
        expected_keys.update(("stepsecurity", mode, "privacy", i) for mode in ("audit", "block") for i in (1, 2))
        expected_keys.add(("stepsecurity", "block", "startup-failure", 1))
    elif profile != "cancellation":
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
    observer_path = root / "observer-final.json"
    observers = json.loads(observer_path.read_text()) if observer_path.exists() else []
    privacy = []
    for tool in ("baseline", "field-cage", "cargowall", "stepsecurity"):
        cohort = [item for item in observers if f"Benchmark {tool} " in item["job"]]
        finals = [record for item in cohort for record in item["records"]]
        modes = []
        for mode in ("audit", "block"):
            selected = [record for item in cohort if f"Benchmark {tool} {mode} " in item["job"] for record in item["records"]]
            if selected:
                modes.append({
                    "mode": mode, "final_job_records": len(selected),
                    "vendor_dns_names": sorted({name for record in selected for name in record.get("vendor_dns_names", [])}),
                })
        privacy.append({
            "tool": tool, "jobs_with_final_record": sum(bool(item["records"]) for item in cohort),
            "jobs_without_final_record": sum(not item["records"] for item in cohort),
            "vendor_dns_names": sorted({name for record in finals for name in record.get("vendor_dns_names", [])}),
            "observer_errors": [error for record in finals for error in record.get("errors", [])],
            "truncated_destination_lists": sum(record.get("destination_list_truncated", False) for record in finals),
            "modes": modes,
            "limits": "DNS names identify observed destinations, not transmitted TLS payloads or all vendor IPs.",
        })
    telemetry = []
    for record in records:
        if record["kind"] == "privacy":
            suffix = f"Benchmark stepsecurity {record['mode']} privacy {record['iteration']}"
            finals = [final for item in observers if item["job"].endswith(suffix) for final in item["records"]]
            telemetry.append({
                "mode": record["mode"], "telemetry_disabled": record.get("telemetry_disabled"),
                "final_records": len(finals),
                "vendor_dns_names": sorted({name for final in finals for name in final.get("vendor_dns_names", [])}),
            })
    run_path = root / "run.json"
    run = json.loads(run_path.read_text()) if run_path.exists() else {}
    if run:
        coherent = coherent and all(
            record.get("run_id") == str(run["id"])
            and record.get("attempt") == str(run["run_attempt"])
            and record.get("sha") == run["head_sha"]
            for record in records
        )
    return {
        "source": {key: run.get(key) for key in ("id", "html_url", "head_sha", "run_attempt", "status", "conclusion")},
        "profile": profile, "expected_case_jobs": expected, "result_artifacts": len(records),
        "missing_result_artifacts": missing,
        "log_recovered_results": [record["artifact"] for record in records if record.get("evidence_source") == "job-log"],
        "missing_cases": sorted(expected_keys - actual_keys),
        "unexpected_cases": sorted(actual_keys - expected_keys),
        "coverage_complete": actual_keys == expected_keys and len(records) == expected and coherent and not missing and all(record.get("completed") for record in records),
        "builds": builds, "cases": cases, "faults": faults,
        "case_status_counts": dict(Counter(case["status"] for case in cases)),
        "performance": measurements, "cleanup": cleanup,
        "reporting_failures": reporting_failures, "completion_supervision": supervision,
        "post_cleanup_connectivity": [{"job": item["job"], "checks": final["cleanup_connectivity"]} for item in observers for final in item["records"] if final.get("cleanup_connectivity")],
        "telemetry_comparison": telemetry,
        "privacy": privacy,
        "stepsecurity_agent_builds": sorted(set(tier)),
        "community_only_test": "Enterprise is the accepted test target for this follow-up; Community differences are documentary, not an equivalence claim." if profile in ("gaps", "udp") else "inconclusive: the pinned action exposes no supported input to force the Community agent; no organization license or App was changed",
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
        f"GitHub run: {report['source'].get('html_url')}. Server status: **{report['source'].get('status')} / {report['source'].get('conclusion')}**.", "",
        "## Functional cases", "",
        "| Tool | Mode | Case | Passed | Failed | Unsupported | Inconclusive |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    grouped = defaultdict(Counter)
    for case in report["cases"]:
        grouped[(case["tool"], case["mode"], case["kind"], case["case"])][case["status"]] += 1
    for (tool, mode, kind, case), counts in sorted(grouped.items()):
        lines.append(f"| {tool} | {mode} | {kind}: {case} | " + " | ".join(str(counts[key]) for key in ("passed", "failed", "unsupported", "inconclusive")) + " |")
    lines.extend(["", "## Fault cases", "", "| Tool | Fault | Status | Meaning |", "| --- | --- | --- | --- |"])
    for fault in report["faults"]:
        reason = fault["reason"].replace("\n", " ").replace("|", "\\|")
        lines.append(f"| {fault['tool']} | {fault['kind']} | {fault['status']} | {reason} |")
    lines.extend(["", "## Completion and evidence reliability", ""])
    lines.extend("- " + item["job"] + ": " + item["reason"] for item in report["reporting_failures"])
    if not report["reporting_failures"]:
        lines.append("No job-completion reporting failure was observed.")
    if report["log_recovered_results"]:
        lines.append("Results recovered from job logs rather than uploaded raw artifacts: " + ", ".join(report["log_recovered_results"]) + ". Native/packet files may be unavailable.")
    if report["telemetry_comparison"]:
        lines.extend(["", "## Fixed-mode telemetry comparison", "", "| Mode | disable-telemetry | Final records | Vendor DNS names |", "| --- | --- | --- | --- |"])
        for item in report["telemetry_comparison"]:
            lines.append(f"| {item['mode']} | {item['telemetry_disabled']} | {item['final_records']} | {', '.join(item['vendor_dns_names'])} |")
    if report["post_cleanup_connectivity"]:
        lines.extend(["", "## Connectivity after native cleanup", "", "| Job | DNS successful / total | HTTPS successful / total |", "| --- | --- | --- |"])
        for item in report["post_cleanup_connectivity"]:
            dns = [check for check in item["checks"] if check["command"][0] == "getent"]
            https = [check for check in item["checks"] if check["command"][0] == "curl"]
            lines.append(f"| {item['job']} | {sum(check['exit_code'] == 0 for check in dns)}/{len(dns)} | {sum(check['exit_code'] == 0 for check in https)}/{len(https)} |")
        lines.extend(["", "Totals include allowed and excluded hosts. A guard may deliberately remain active after its post step; excluded-host failure is not itself a cleanup defect. Inspect the allowed example.org control separately."])
    lines.extend(["", "## Performance by matched environment", "", "| Tool | Mode | Cache | Samples | Median build seconds | Median install seconds | Image / CPU |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for sample in report["performance"]:
        lines.append(f"| {sample['tool']} | {sample['mode']} | {sample['cache']} | {sample['samples']} | {sample['metrics']['wall_seconds']['median']:.2f} | {sample['metrics']['install_seconds']['median']:.2f} | {sample['environment'][0]} / {sample['environment'][2]} |")
    lines.extend(["", "## Tier and interpretation", "", report["community_only_test"], ""])
    lines.extend(report["stepsecurity_agent_builds"])
    lines.extend(["", "## Independent observer", "", "| Tool | Mode | Final job records | Vendor DNS names |", "| --- | --- | --- | --- |"])
    for item in report["privacy"]:
        for mode in item["modes"]:
            lines.append(f"| {item['tool']} | {mode['mode']} | {mode['final_job_records']} | {', '.join(mode['vendor_dns_names']) or 'none observed'} |")
    lines.extend(["", "| Tool | Missing final records | Observer errors | Truncated destination lists |", "| --- | --- | --- | --- |"])
    for item in report["privacy"]:
        lines.append(f"| {item['tool']} | {item['jobs_without_final_record']} | {len(item['observer_errors'])} | {item['truncated_destination_lists']} |")
    lines.extend(["", *["- " + item for item in report["limits"]], ""])
    if report["missing_result_artifacts"]:
        lines.extend(["## Missing/incomplete results", "", *["- " + item for item in report["missing_result_artifacts"]]])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--profile", choices=("full", "smoke", "cancellation", "gaps", "udp"), required=True)
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
