import argparse
import json
import os
from pathlib import Path
import re
import sys

from verify_runtime_evidence import read_jsonl


NETWORK_ERRORS = {
    "EACCES", "EPERM", "ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED",
    "ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT",
}


def verify(tool, mode, build, hook, lifecycle, events, dns):
    if tool not in ("stepsecurity", "field-cage", "cargowall") or mode not in ("audit", "block"):
        raise ValueError("Unsupported tool or mode")
    for stage in ("install", "lint", "typecheck", "test", "build", "smoke"):
        if build.get(stage) != "success":
            raise ValueError(f"The legitimate build did not complete {stage}")
    if hook.get("domain") != "example.com" or not isinstance(hook.get("pid"), int):
        raise ValueError("Missing installed-dependency request identity")
    if mode == "audit":
        if lifecycle.get("exit_code") != 0 or hook.get("exit_code") != 0 or hook.get("http_status") != 200:
            raise ValueError("The audit lifecycle hook did not complete its HTTPS request")
    elif lifecycle.get("exit_code", 0) == 0 or hook.get("exit_code") != 1 or hook.get("error_code") not in NETWORK_ERRORS:
        raise ValueError("The block lifecycle hook did not fail with an expected network error")

    if tool == "stepsecurity":
        registry = [
            line for line in events
            if re.search(r"\bdomain=registry\.npmjs\.org\.(?:\s|$)", line)
            and ("[dns-request]" in line or "[dns-response]" in line)
        ]
        expected_event = "[dns-request-dropped]" if mode == "block" else "[dns-request]"
        excluded = [
            line for line in events
            if re.search(r"\bdomain=example\.com\.(?:\s|$)", line)
            and expected_event in line and re.search(r"\bexe=\S*node(?:\s|$)", line)
        ]
    elif tool == "field-cage":
        registry = [
            event for event in events
            if event.get("domain") == "registry.npmjs.org"
            and event.get("port") == 443 and event.get("verdict") == "ALLOW"
        ]
        excluded = [
            event for event in events
            if event.get("domain") == "example.com" and event.get("port") == 443
            and event.get("tgid") == hook["pid"]
            and event.get("verdict") in ("DENY(not-in-policy)", "DENY(no-domain)")
        ]
    else:
        registry = [
            event for event in events
            if event.get("dst_hostname") == "registry.npmjs.org"
            and event.get("dst_port") == 443 and event.get("blocked") is False
            and event.get("event_type") in ("connection_allowed", "connection_late_allowed")
        ]
        excluded = [
            event for event in events
            if event.get("dst_hostname") == "example.com"
            and event.get("event_type") in ("dns_blocked", "connection_blocked")
            and event.get("blocked") is (mode == "block")
            and (mode == "block" or event.get("would_deny") is True)
        ]
    if not registry or not excluded:
        raise ValueError("Missing registry observation or excluded-domain agent evidence")
    for domain in ("registry.npmjs.org.", "example.com."):
        if domain not in dns:
            raise ValueError(f"Missing plain-DNS observation for {domain}")
    vendor_dns_observed = bool(re.search(r"\b(stepsecurity\.io|codecargo\.com)\b", dns, re.IGNORECASE))
    if tool != "stepsecurity" and vendor_dns_observed:
        raise ValueError("Security-vendor domain observed in the local-first build capture")
    return {
        "tool": tool,
        "mode": mode,
        "legitimate_build": build,
        "installed_dependency_hook": hook,
        "lifecycle_command": lifecycle,
        "registry_evidence": registry,
        "excluded_domain_evidence": excluded,
        "vendor_dns_observed": vendor_dns_observed,
        "limits": "Plain-DNS observation is not a zero-egress guarantee. "
                  "StepSecurity observations are DNS records, not portal verification; "
                  "its node executable attribution is not exact PID correlation. "
                  "CargoWall DNS records have no process attribution.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True, choices=("stepsecurity", "field-cage", "cargowall"))
    parser.add_argument("--mode", required=True, choices=("audit", "block"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    directory = args.directory
    try:
        events = (
            (directory / "agent.log").read_text().splitlines()
            if args.tool == "stepsecurity" else read_jsonl(directory / "events.jsonl")
        )
        report = verify(
            args.tool, args.mode,
            json.loads((directory / "build.json").read_text()),
            json.loads((directory / "hook.json").read_text()),
            json.loads((directory / "lifecycle-command.json").read_text()),
            events, (directory / "dns.log").read_text(),
        )
    except (OSError, ValueError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    report["github"] = {
        key: os.environ[key] for key in (
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"
        ) if key in os.environ
    }
    (directory / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(
            f"\n## Representative Node build: {args.tool}, {args.mode}\n\n"
            "Locked dependency installation, DX lint, typecheck, Vitest, compilation "
            "and compiled smoke test passed under protection.\n\n"
            f"Installed dependency postinstall exit: {report['lifecycle_command']['exit_code']}. "
            "Registry and excluded-domain agent observations verified.\n\n"
            "**No exfiltration or malicious domain was used.** The approved postinstall "
            "was invoked explicitly after an ignore-scripts install. This is a controlled "
            "runtime test, not evidence that pnpm's default script controls are bypassed.\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
