"""Download one explicitly selected run and retain logs even when artifact upload failed."""

import argparse
import json
from pathlib import Path
import re
import subprocess


REPOSITORY = "pagopa-dx/ss-pilot"


def api(endpoint):
    return subprocess.run(
        ["gh", "api", endpoint, "--allow-escape-sequences"],
        text=True, capture_output=True, timeout=90, check=True,
    ).stdout


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    root = args.directory
    root.mkdir(parents=True, exist_ok=True)
    run = json.loads(api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}"))
    if run["status"] != "completed":
        raise SystemExit("Run must finish before collecting final native cleanup evidence")
    (root / "run.json").write_text(json.dumps(run, indent=2))
    subprocess.run(
        ["gh", "run", "download", str(args.run_id), "--repo", REPOSITORY, "--dir", str(root)],
        check=True, timeout=180,
    )
    jobs = []
    page = 1
    while True:
        batch = json.loads(api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}/jobs?per_page=100&page={page}"))["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    (root / "jobs.json").write_text(json.dumps(jobs, indent=2))
    log_root = root / "job-logs"
    log_root.mkdir(exist_ok=True)
    observers = []
    for job in jobs:
        if "Benchmark " not in job["name"]:
            continue
        text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", api(f"repos/{REPOSITORY}/actions/jobs/{job['id']}/logs"))
        (log_root / f"{job['id']}.log").write_text(text)
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
