import argparse
import json
import os
from pathlib import Path
import re
import sys


def read_jsonl(path):
    records = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{number}: expected a JSON object")
        records.append(record)
    if not records:
        raise ValueError(f"{path}: no records")
    return records


def verify(tool, mode, workload, events, dns):
    if tool not in ("field-cage", "cargowall") or mode not in ("audit", "block"):
        raise ValueError("Unsupported tool or mode")
    if len(workload) != 2 or {r.get("domain") for r in workload} != {
        "api.github.com", "example.com"
    }:
        raise ValueError("Expected exactly one request to each workload domain")
    requests = {record["domain"]: record for record in workload}
    for domain, record in requests.items():
        if mode == "block" and domain == "example.com":
            if record.get("curl_exit") not in (6, 7, 28):
                raise ValueError("example.com did not fail with an expected transport error")
        elif record.get("curl_exit") != 0 or not re.fullmatch(
            r"2[0-9]{2}", record.get("http_status", "")
        ):
            raise ValueError(f"{domain} did not return a successful HTTP response")

    host_key = "domain" if tool == "field-cage" else "dst_hostname"
    selected = {}
    for domain in requests:
        matches = [
            event for event in events
            if event.get(host_key, "").rstrip(".").lower() == domain
        ]
        if tool == "field-cage":
            matches = [
                event for event in matches
                if event.get("port") == 443
                and event.get("tgid") == requests[domain].get("pid")
                and event.get("comm") == "curl"
            ]
            if domain == "api.github.com":
                matches = [event for event in matches if event.get("verdict") == "ALLOW"]
            elif mode == "block":
                matches = [
                    event for event in matches
                    if event.get("verdict") in ("DENY(not-in-policy)", "DENY(no-domain)")
                ]
        elif domain == "api.github.com":
            matches = [
                event for event in matches
                if event.get("event_type") in ("connection_allowed", "connection_late_allowed")
                and event.get("dst_port") == 443
                and event.get("blocked") is False
            ]
        else:
            matches = [
                event for event in matches
                if event.get("blocked") is (mode == "block")
                and event.get("event_type") in (
                    "connection_allowed", "connection_late_allowed",
                    "connection_blocked", "dns_blocked"
                )
            ]
        if not matches:
            raise ValueError(f"No matching agent evidence for {domain} in {mode} mode")
        selected[domain] = matches

    for domain in requests:
        if domain + "." not in dns:
            raise ValueError(f"No independent plain-DNS observation for {domain}")
    if re.search(r"\b(stepsecurity\.io|codecargo\.com)\b", dns, re.IGNORECASE):
        raise ValueError("Security-vendor domain observed in DNS capture; inspect dns.log")

    return {
        "tool": tool,
        "mode": mode,
        "workload": workload,
        "agent_evidence": selected,
        "vendor_dns_observed": False,
        "dns_scope": "Plain DNS only, from before installation to evidence collection; "
                     "not proof of zero egress, including cached DNS, direct IP or DoH.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", choices=("field-cage", "cargowall"), required=True)
    parser.add_argument("--mode", choices=("audit", "block"), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(
            args.tool, args.mode,
            read_jsonl(args.directory / "workload.jsonl"),
            read_jsonl(args.directory / "events.jsonl"),
            (args.directory / "dns.log").read_text(),
        )
    except (OSError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    report["github"] = {
        key: os.environ[key] for key in (
            "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"
        ) if key in os.environ
    }
    (args.directory / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(
            f"\n## {args.tool}: {args.mode}\n\n"
            "Both workload outcomes and domain-specific local agent evidence verified.\n\n"
            "No StepSecurity/CodeCargo domain was observed in the plain-DNS capture. "
            "**This is not proof of zero vendor communication.** "
            "Inspect the raw logs and JSON artifact for this run.\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
