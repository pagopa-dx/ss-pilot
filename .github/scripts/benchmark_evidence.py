"""Normalize native observations without confusing audit verdicts with enforcement."""

from datetime import datetime
import re
from urllib.parse import urlparse


def matches(tool, probe, events):
    domain = probe.get("domain") or urlparse(probe.get("url", "")).hostname
    port = probe.get("port") or urlparse(probe.get("url", "")).port or (443 if probe.get("url", "").startswith("https:") else 80)
    if probe.get("case") == "redirect-to-excluded":
        domain, port = "example.com", 443
    pid = probe.get("pid")
    result = []
    for event in events:
        if tool == "field-cage":
            target = event.get("domain") == domain or (probe.get("ip") and event.get("ip") == probe["ip"])
            if target and event.get("port") == port and event.get("tgid") == pid:
                result.append(event)
        elif tool == "cargowall":
            target = event.get("dst_hostname") == domain or (probe.get("ip") and event.get("dst_ip") == probe["ip"])
            timestamp = event.get("timestamp")
            try:
                normalized = re.sub(r"(\.\d{6})\d+(?=Z|[+-]|$)", r"\1", timestamp) if timestamp else None
                at = datetime.fromisoformat(normalized.replace("Z", "+00:00")).timestamp() if normalized else None
            except ValueError:
                at = None
            # DNS events have no PID; require their own bounded probe time window.
            identity = event.get("pid") == pid if event.get("pid") else (
                at is not None and probe.get("started_at", 0) <= at <= probe.get("finished_at", 0)
            )
            if target and identity and event.get("dst_port", port) == port:
                result.append(event)
        elif tool == "stepsecurity":
            process = pid is not None and re.search(rf"\bpid[=:]\s*{pid}(?:,|\s|$)", event)
            dns = domain and re.search(rf"\bdomain={re.escape(domain)}\.(?:\s|$)", event)
            ips = set(probe.get("target_ips", []))
            if probe.get("ip"):
                ips.add(probe["ip"])
            destination = re.search(r"\bip=(\S+)\s+port=(\d+)\b", event)
            packet = "[net-dropped]" in event and destination and destination[1] in ips and int(destination[2]) == port
            if process and (dns or packet):
                result.append(event)
    return result


def denied(tool, evidence, mode):
    if tool == "field-cage":
        return any(event.get("verdict", "").startswith("DENY(") for event in evidence)
    if tool == "cargowall":
        return any(
            event.get("event_type") in ("dns_blocked", "connection_blocked")
            and event.get("blocked") is (mode == "block")
            and (mode == "block" or event.get("would_deny") is True)
            for event in evidence
        )
    return any("[dns-request-dropped]" in line or "[net-dropped]" in line for line in evidence) if mode == "block" else any("[dns-request]" in line for line in evidence)


def classify(tool, mode, probe, baseline_reached, evidence):
    if probe.get("unavailable"):
        return "unsupported", probe["unavailable"]
    if probe.get("harness_error"):
        return "inconclusive", probe["harness_error"]
    expect_reached = tool == "baseline" or mode == "audit" or probe["allowed"]
    if expect_reached:
        if not probe.get("reached"):
            if baseline_reached and mode == "block" and denied(tool, evidence, mode):
                return "failed", "Allowed traffic was denied despite a successful unprotected control"
            return "inconclusive", "Expected transport success; cannot separate guard interference from endpoint/environment failure"
        if tool != "baseline" and not probe["allowed"] and not denied(tool, evidence, mode):
            return "inconclusive", "Request succeeded but excluded-policy native observation is missing"
        return "passed", "Transport result and required native observation agree"
    if probe.get("reached"):
        return "failed", "Excluded traffic reached its destination: coverage/policy gap, not necessarily a product defect"
    if not baseline_reached:
        return (
            "unsupported" if probe["case"] in ("excluded-ipv6", "alternate-dns-udp", "docker-bridge", "docker-host") else "inconclusive",
            "No successful matching unprotected control",
        )
    if denied(tool, evidence, mode):
        return "passed", "Request failed with correlated native denial and a successful unprotected control"
    return "inconclusive", "Transport failed without sufficient correlated native denial"
