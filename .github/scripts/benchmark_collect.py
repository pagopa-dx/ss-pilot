"""Download one explicitly selected run and retain logs even when artifact upload failed."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


REPOSITORY = "pagopa-dx/ss-pilot"


def api(endpoint):
    for attempt in range(3):
        result = subprocess.run(
            ["gh", "api", endpoint, "--allow-escape-sequences"],
            text=True, capture_output=True, timeout=90,
        )
        if result.returncode == 0:
            return result.stdout
        if attempt < 2 and re.search(r"HTTP 50[0234]", result.stderr):
            print(f"Transient GitHub response for {endpoint}; retrying: {result.stderr.strip()}")
            time.sleep(attempt + 1)
            continue
        raise RuntimeError(f"gh api {endpoint}: {result.stderr.strip()}")


def marker(text, name):
    records = []
    for line in text.splitlines():
        if name + " " in line:
            data = line.split(name + " ", 1)[1]
            try:
                records.append(json.loads(data))
            except json.JSONDecodeError as error:
                raise ValueError(f"Malformed or truncated {name} record") from error
    return records


def finished_steps(jobs):
    cohort = [job for job in jobs if "Benchmark " in job["name"] and job.get("conclusion") != "skipped"]
    return bool(cohort) and all(
        job["status"] == "completed" or any(
            step["name"] == "Complete job" and step["status"] == "completed"
            for step in job.get("steps", [])
        ) for job in cohort
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--allow-finished-steps", action="store_true", help="Collect a reporting-stuck run only after every case completed its final native post step")
    parser.add_argument("--supervision", type=Path, help="Retain the external completion/force-cancellation observation for this run")
    args = parser.parse_args()
    root = args.directory
    root.mkdir(parents=True, exist_ok=True)
    if (root / "download.json").exists() and json.loads((root / "download.json").read_text())["run_id"] != args.run_id:
        raise SystemExit("Evidence directory already contains a different run")
    run = json.loads(api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}"))
    if run["status"] != "completed" and not args.allow_finished_steps:
        raise SystemExit("Run must finish before collecting final native cleanup evidence")
    jobs = []
    page = 1
    while True:
        batch = json.loads(api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}/jobs?per_page=100&page={page}"))["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    if run["status"] != "completed" and not finished_steps(jobs):
        raise SystemExit("Cannot snapshot active/queued cases; all native post steps must finish first")
    (root / "run.json").write_text(json.dumps(run, indent=2))
    (root / "collection-state.json").write_text(json.dumps({
        "server_status": run["status"], "server_conclusion": run["conclusion"],
        "all_case_step_sequences_finished": finished_steps(jobs),
        "reporting_stuck": run["status"] != "completed",
    }, indent=2))
    if args.supervision:
        supervision = json.loads(args.supervision.read_text())
        if supervision["run_id"] != args.run_id:
            raise SystemExit("Completion supervision belongs to a different run")
        (root / "completion-supervision.json").write_text(json.dumps(supervision, indent=2))
    if not (root / "download.json").exists():
        with tempfile.TemporaryDirectory(prefix="artifact-download-", dir=root) as directory:
            subprocess.run(
                ["gh", "run", "download", str(args.run_id), "--repo", REPOSITORY, "--dir", directory],
                check=True, timeout=180,
            )
            for folder in Path(directory).iterdir():
                shutil.copytree(folder, root / folder.name, dirs_exist_ok=True)
        (root / "download.json").write_text(json.dumps({"run_id": args.run_id}))
    (root / "jobs.json").write_text(json.dumps(jobs, indent=2))
    log_root = root / "job-logs"
    log_root.mkdir(exist_ok=True)
    observers = []
    for job in jobs:
        if "Benchmark " not in job["name"] or job.get("conclusion") == "skipped":
            continue
        log_file = log_root / f"{job['id']}.log"
        text = log_file.read_text() if log_file.exists() else re.sub(
            r"\x1b\[[0-9;]*[a-zA-Z]", "", api(f"repos/{REPOSITORY}/actions/jobs/{job['id']}/logs"),
        )
        log_file.write_text(text)
        final = marker(text, "BENCHMARK_OBSERVER_FINAL")
        observers.append({"job": job["name"], "id": job["id"], "records": final})
        results = marker(text, "BENCHMARK_CASE_RESULT")
        if not results:
            continue
        report = results[-1]
        artifact = f"benchmark-{report['tool']}-{report['mode']}-{report['kind']}-{report['iteration']}-{report['attempt']}"
        folder = root / artifact
        if not (folder / "result.json").exists():
            folder.mkdir(exist_ok=True)
            report["evidence_source"] = "job-log"
            report["evidence_limits"] = "Artifact upload did not preserve the result; raw packet/native files may be unavailable. Do not infer native probe evidence from this result alone."
            (folder / "result.json").write_text(json.dumps(report, indent=2))
    (root / "observer-final.json").write_text(json.dumps(observers, indent=2))
    print(json.dumps({"run": args.run_id, "jobs": len(jobs), "final_observer_records": sum(bool(item["records"]) for item in observers)}, indent=2))


if __name__ == "__main__":
    main()
