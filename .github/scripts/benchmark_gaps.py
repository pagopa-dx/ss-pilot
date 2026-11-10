"""Focused harmless probes; no new infrastructure or runner hardware selection."""

import ipaddress
import json
import subprocess
from urllib.parse import urlparse

from benchmark_probes import curl_probe, udp_probe


def addresses(root):
    resolved = json.loads((root / "pre-resolved.json").read_text())
    return {
        host: [str(ipaddress.ip_address(item["address"])) for item in values if isinstance(item, dict)]
        for host, values in resolved.items() if isinstance(values, list)
    }


def diagnostics():
    records = []
    for args in (
        ["resolvectl", "status"],
        ["sudo", "iptables-save", "-c"],
        ["sudo", "ip6tables-save", "-c"],
        ["sudo", "nft", "list", "ruleset"],
    ):
        result = subprocess.run(args, text=True, capture_output=True, timeout=10)
        records.append({
            "command": args, "exit_code": result.returncode, "stdout": result.stdout[:100000],
            "stderr": result.stderr[:2000], "truncated": len(result.stdout) > 100000,
        })
    return records


def network(root, kind):
    resolved = addresses(root)
    records = []
    shared = set(resolved.get("example.org", [])) & set(resolved.get("www.example.org", []))
    (root / "gap-addresses.json").write_text(json.dumps({
        "pre_guard": resolved, "shared_allowed_subdomain_ips": sorted(shared),
        "limits": "Public CDN addresses are observed, not controlled; this tests order and explicit address selection, not all DNS/cache behavior.",
    }, indent=2))

    def request(name, url, allowed, pinned=False):
        host = urlparse(url).hostname
        ipv4 = [ip for ip in resolved.get(host, []) if ipaddress.ip_address(ip).version == 4]
        flags = []
        if pinned:
            if not ipv4:
                records.append({"case": name, "allowed": allowed, "reached": False, "unavailable": "No pre-guard IPv4 address"})
                return
            flags = ["--resolve", f"{host}:443:{ipv4[0]}"]
        record = curl_probe(name, url, flags, allowed)
        record["target_ips"] = resolved.get(host, [])
        if pinned:
            record["ip"] = ipv4[0]
        records.append(record)

    (root / "gap-rules-before.json").write_text(json.dumps(diagnostics(), indent=2))
    if kind == "privacy":
        request("allowed-https", "https://example.org/", True)
        request("excluded-https", "https://example.com/", False)
    else:
        sequence = [
            ("allowed-https", "https://example.org/", True),
            ("subdomain-exactness", "https://www.example.org/", False),
        ]
        if kind == "gap-excluded-first":
            sequence.reverse()
        for name, url, allowed in sequence:
            request(name, url, allowed, pinned=kind == "gap-pinned")
        request("excluded-https", "https://example.com/", False)
        request("allowed-host-port-80", "http://example.org/", False)
        request("pre-resolved-excluded", "https://example.com/", False, pinned=True)
        ipv4 = [ip for ip in resolved.get("example.com", []) if ipaddress.ip_address(ip).version == 4]
        if ipv4:
            record = curl_probe("direct-ip-excluded", f"http://{ipv4[0]}/", [], False)
            record["ip"] = ipv4[0]
            records.append(record)
        else:
            records.append({"case": "direct-ip-excluded", "allowed": False, "unavailable": "No pre-guard IPv4 address"})
        records.append(udp_probe())
    (root / "gap-rules-after.json").write_text(json.dumps(diagnostics(), indent=2))
    (root / "probes.json").write_text(json.dumps(records, indent=2))
    return records
