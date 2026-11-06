from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from verify_runtime_evidence import read_jsonl, verify


class RuntimeEvidenceTests(unittest.TestCase):
    def sample(self, tool, mode):
        workload = [
            {"domain": "api.github.com", "curl_exit": 0, "http_status": "200", "pid": 100},
            {"domain": "example.com", "curl_exit": 0, "http_status": "200", "pid": 101},
        ]
        if mode == "block":
            workload[1].update(curl_exit=6, http_status="000")
        if tool == "field-cage":
            events = [
                {"domain": record["domain"], "port": 443, "tgid": record["pid"],
                 "comm": "curl", "verdict": "ALLOW" if i == 0 else "DENY(not-in-policy)"}
                for i, record in enumerate(workload)
            ]
        else:
            events = [
                {"dst_hostname": "api.github.com", "dst_port": 443,
                 "event_type": "connection_allowed", "blocked": False},
                {"dst_hostname": "example.com", "event_type": "dns_blocked",
                 "blocked": mode == "block", "would_deny": mode == "audit"},
            ]
        dns = "A? api.github.com.\nA? example.com.\n"
        return workload, events, dns

    def test_both_tools_and_modes(self):
        for tool in ("field-cage", "cargowall"):
            for mode in ("audit", "block"):
                with self.subTest(tool=tool, mode=mode):
                    report = verify(tool, mode, *self.sample(tool, mode))
                    self.assertEqual(report["mode"], mode)
                    self.assertFalse(report["vendor_dns_observed"])

    def test_curl_failure_without_agent_denial_is_rejected(self):
        for tool in ("field-cage", "cargowall"):
            workload, events, dns = self.sample(tool, "block")
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "agent evidence"):
                verify(tool, "block", workload, events[:1], dns)

    def test_successful_http_error_does_not_count_as_blocking(self):
        workload, events, dns = self.sample("cargowall", "block")
        workload[1].update(curl_exit=0, http_status="403")
        with self.assertRaisesRegex(ValueError, "transport error"):
            verify("cargowall", "block", workload, events, dns)

    def test_wrong_field_cage_process_is_rejected(self):
        workload, events, dns = self.sample("field-cage", "block")
        events = deepcopy(events)
        events[1]["tgid"] = 999
        with self.assertRaisesRegex(ValueError, "agent evidence"):
            verify("field-cage", "block", workload, events, dns)

    def test_hypothetical_cargowall_denial_is_not_actual_blocking(self):
        workload, events, dns = self.sample("cargowall", "block")
        events[1].update(blocked=False, would_deny=True)
        with self.assertRaisesRegex(ValueError, "agent evidence"):
            verify("cargowall", "block", workload, events, dns)

    def test_missing_capture_and_vendor_queries_are_rejected(self):
        workload, events, dns = self.sample("field-cage", "audit")
        with self.assertRaisesRegex(ValueError, "plain-DNS"):
            verify("field-cage", "audit", workload, events, "")
        for vendor in ("agent.api.stepsecurity.io.", "app.codecargo.com."):
            with self.subTest(vendor=vendor), self.assertRaisesRegex(ValueError, "vendor domain"):
                verify("field-cage", "audit", workload, events, dns + vendor)

    def test_invalid_empty_and_non_object_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            for content in ("", "{", "[]"):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    read_jsonl(path)


if __name__ == "__main__":
    unittest.main()
