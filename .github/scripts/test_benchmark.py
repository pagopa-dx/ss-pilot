import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmark_evidence import classify, denied, matches
from benchmark_collect import marker
from benchmark_probes import CASES, curl_probe
from benchmark_report import aggregate
from benchmark_runner import plan, resolve_agent_pid


class BenchmarkTests(unittest.TestCase):
    def test_log_evidence_is_explicit_and_malformed_records_are_rejected(self):
        self.assertEqual(marker('timestamp BENCHMARK_CASE_RESULT {"tool":"baseline"}', "BENCHMARK_CASE_RESULT"), [{"tool": "baseline"}])
        with self.assertRaises(ValueError):
            marker("timestamp BENCHMARK_CASE_RESULT {truncated", "BENCHMARK_CASE_RESULT")

    def test_field_cage_sudo_wrapper_resolves_to_the_unique_actual_agent(self):
        tree = {
            10: ("/usr/bin/sudo", [11]),
            11: ("/usr/bin/sudo", [12]),
            12: ("/tmp/field-cage_linux_amd64", []),
        }
        self.assertEqual(resolve_agent_pid("field-cage", 10, tree.__getitem__), 12)
        self.assertEqual(resolve_agent_pid("field-cage", 12, tree.__getitem__), 12)
        with self.assertRaises(ValueError):
            resolve_agent_pid("cargowall", 10, tree.__getitem__)
        tree[11] = ("/usr/bin/sudo", [12, 13])
        tree[13] = ("/tmp/field-cage_linux_amd64", [])
        with self.assertRaises(ValueError):
            resolve_agent_pid("field-cage", 10, tree.__getitem__)

    def test_full_plan_has_exactly_one_hundred_isolated_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_SHA": "fixed"}):
                plan("full")
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            baseline = json.loads(values["baseline"])["include"]
            guards = json.loads(values["guards"])["include"]
            self.assertEqual(len(baseline) + 3 * len(guards), 100)
            self.assertEqual(sum(case["kind"] == "performance" for case in baseline), 10)
            self.assertEqual(sum(case["kind"] == "functional" for case in guards), 6)
            self.assertEqual(len({(case["kind"], case["iteration"], case["mode"]) for case in guards}), len(guards))

    def test_smoke_and_cancellation_plan_sizes(self):
        for profile, expected in (("smoke", 23), ("cancellation", 3)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                    plan(profile)
                values = dict(line.split("=", 1) for line in output.read_text().splitlines())
                count = 3 * len(json.loads(values["guards"])["include"])
                if profile != "cancellation":
                    count += len(json.loads(values["baseline"])["include"])
                self.assertEqual(count, expected)

    def test_no_transport_error_alone_proves_blocking(self):
        probe = {"case": "excluded-https", "allowed": False, "reached": False}
        self.assertEqual(classify("field-cage", "block", probe, True, [])[0], "inconclusive")
        proof = [{"verdict": "DENY(not-in-policy)"}]
        self.assertEqual(classify("field-cage", "block", probe, True, proof)[0], "passed")
        self.assertEqual(classify("field-cage", "block", probe, False, proof)[0], "inconclusive")

    def test_actual_excluded_reach_is_a_gap_even_without_native_logs(self):
        probe = {"case": "allowed-host-port-80", "allowed": False, "reached": True}
        self.assertEqual(classify("field-cage", "block", probe, False, [])[0], "failed")

    def test_audit_policy_decisions_are_not_actual_blocks(self):
        evidence = [{"event_type": "dns_blocked", "would_deny": True, "blocked": False}]
        self.assertTrue(denied("cargowall", evidence, "audit"))
        self.assertFalse(denied("cargowall", evidence, "block"))
        probe = {"case": "excluded-https", "allowed": False, "reached": True}
        self.assertEqual(classify("cargowall", "audit", probe, True, evidence)[0], "passed")
        self.assertEqual(classify("cargowall", "audit", probe, True, [])[0], "inconclusive")

    def test_cargowall_dns_requires_its_probe_time_window(self):
        probe = {"url": "https://example.com/", "pid": 42, "started_at": 100, "finished_at": 101}
        base = {"event_type": "dns_blocked", "dst_hostname": "example.com"}
        wrong = {**base, "timestamp": "1970-01-01T00:01:30Z"}
        correct = {**base, "timestamp": "1970-01-01T00:01:40Z"}
        self.assertEqual(matches("cargowall", probe, [wrong, correct]), [correct])

    def test_process_and_port_attribution_cannot_be_substituted(self):
        probe = {"url": "https://example.com/", "pid": 42}
        event = {"domain": "example.com", "port": 443, "tgid": 42}
        self.assertEqual(matches("field-cage", probe, [event]), [event])
        self.assertEqual(matches("field-cage", probe, [{**event, "tgid": 43}, {**event, "port": 80}]), [])
        lines = [
            "[dns-request-dropped] pid=42 exe=/bin/curl domain=example.com. matchedPolicy=NONE",
            "[dns-request-dropped] pid=420 exe=/bin/curl domain=example.com. matchedPolicy=NONE",
        ]
        self.assertEqual(matches("stepsecurity", probe, lines), lines[:1])

    def test_environment_limitations_are_not_successful_blocks(self):
        probe = {"case": "excluded-ipv6", "allowed": False, "reached": False}
        self.assertEqual(classify("stepsecurity", "block", probe, False, [])[0], "unsupported")
        unavailable = {**probe, "unavailable": "Docker daemon unavailable"}
        self.assertEqual(classify("field-cage", "audit", unavailable, True, [])[0], "unsupported")

    def test_positive_control_denial_is_a_failure_when_proven(self):
        probe = {"case": "allowed-https", "allowed": True, "reached": False}
        self.assertEqual(classify("field-cage", "block", probe, True, [{"verdict": "DENY(not-in-policy)"}])[0], "failed")

    def test_http_403_means_transport_reached_not_firewall_blocked(self):
        with patch("benchmark_probes.subprocess.Popen") as popen:
            child = popen.return_value
            child.pid, child.returncode = 123, 0
            child.communicate.return_value = ('{"http_code":403}', "")
            result = curl_probe("allowed-https", "https://example.org/", [], True)
            self.assertTrue(result["reached"])

    def test_empty_or_missing_artifacts_cannot_complete_a_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "benchmark-missing").mkdir()
            report = aggregate(root, [], "full")
            self.assertFalse(report["coverage_complete"])
            self.assertEqual(len(report["missing_cases"]), 100)
            self.assertEqual(report["missing_result_artifacts"], ["benchmark-missing"])

    def test_action_presteps_remain_separated_by_tool(self):
        text = (Path(__file__).parents[1] / "workflows/runtime-benchmark.yml").read_text()
        field = text.split("\n  field-cage:", 1)[1].split("\n  cargowall:", 1)[0]
        cargo = text.split("\n  cargowall:", 1)[1].split("\n  stepsecurity:", 1)[0]
        baseline = text.split("\n  baseline:", 1)[1].split("\n  field-cage:", 1)[0]
        for job in (field, cargo, baseline):
            self.assertNotIn("step-security/harden-runner@", job)
        self.assertEqual(len(CASES), len({case[0] for case in CASES}))


if __name__ == "__main__":
    unittest.main()
