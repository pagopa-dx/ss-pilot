from pathlib import Path
import re
import unittest

from verify_node_build import verify


class NodeBuildEvidenceTests(unittest.TestCase):
    def sample(self, tool, mode):
        build = {stage: "success" for stage in ("install", "lint", "typecheck", "test", "build", "smoke")}
        hook = {"domain": "example.com", "pid": 123, "exit_code": 0, "http_status": 200}
        lifecycle = {"exit_code": 0}
        if mode == "block":
            hook = {"domain": "example.com", "pid": 123, "exit_code": 1, "error_code": "ENOTFOUND"}
            lifecycle = {"exit_code": 1}
        if tool == "stepsecurity":
            event = "dns-request-dropped" if mode == "block" else "dns-request"
            events = [
                "[dns-response] pid=2 exe=node domain=registry.npmjs.org. ip=1.2.3.4",
                f"[{event}] pid=125 exe=/opt/node domain=example.com. matchedPolicy=NONE",
            ]
        elif tool == "field-cage":
            events = [
                {"domain": "registry.npmjs.org", "port": 443, "verdict": "ALLOW"},
                {"domain": "example.com", "port": 443, "verdict": "DENY(not-in-policy)", "tgid": 123},
            ]
        else:
            events = [
                {"dst_hostname": "registry.npmjs.org", "dst_port": 443, "event_type": "connection_allowed", "blocked": False},
                {"dst_hostname": "example.com", "event_type": "dns_blocked", "blocked": mode == "block", "would_deny": mode == "audit"},
            ]
        return build, hook, lifecycle, events, "A? registry.npmjs.org.\nA? example.com.\n"

    def test_each_tool_and_mode(self):
        for tool in ("stepsecurity", "field-cage", "cargowall"):
            for mode in ("audit", "block"):
                with self.subTest(tool=tool, mode=mode):
                    self.assertEqual(verify(tool, mode, *self.sample(tool, mode))["mode"], mode)

    def test_failed_build_is_not_a_successful_security_test(self):
        sample = self.sample("cargowall", "block")
        sample[0]["test"] = "failed"
        with self.assertRaisesRegex(ValueError, "complete test"):
            verify("cargowall", "block", *sample)

    def test_missing_agent_record_does_not_certify_network_failure(self):
        for tool in ("stepsecurity", "field-cage", "cargowall"):
            sample = list(self.sample(tool, "block"))
            sample[3] = sample[3][:1]
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "agent evidence"):
                verify(tool, "block", *sample)

    def test_permissive_audit_policy_is_rejected(self):
        for tool in ("field-cage", "cargowall"):
            sample = self.sample(tool, "audit")
            sample[3][1].update(verdict="ALLOW", would_deny=False)
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "agent evidence"):
                verify(tool, "audit", *sample)

    def test_wrong_field_cage_process_is_rejected(self):
        sample = self.sample("field-cage", "block")
        sample[3][1]["tgid"] = 999
        with self.assertRaisesRegex(ValueError, "agent evidence"):
            verify("field-cage", "block", *sample)

    def test_script_failure_other_than_network_denial_is_rejected(self):
        sample = self.sample("stepsecurity", "block")
        sample[1]["error_code"] = "MODULE_NOT_FOUND"
        with self.assertRaisesRegex(ValueError, "network error"):
            verify("stepsecurity", "block", *sample)

    def test_vendor_dns_is_only_accepted_for_stepsecurity(self):
        for tool in ("stepsecurity", "field-cage", "cargowall"):
            sample = list(self.sample(tool, "audit"))
            sample[4] += "A? agent.api.stepsecurity.io.\n"
            if tool == "stepsecurity":
                self.assertTrue(verify(tool, "audit", *sample)["vendor_dns_observed"])
            else:
                with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "vendor domain"):
                    verify(tool, "audit", *sample)

    def test_security_actions_are_isolated_in_separate_job_definitions(self):
        workflow = (Path(__file__).parents[1] / "workflows" / "node-build-pilot.yml").read_text()
        parts = re.split(
            r"(?m)^  (cargowall-build|field-cage-build|stepsecurity-build):\n",
            workflow,
        )[1:]
        jobs = dict(zip(parts[::2], parts[1::2]))
        actions = {
            "cargowall-build": "code-cargo/cargowall-action@",
            "field-cage-build": "takihito/field-cage@",
            "stepsecurity-build": "step-security/harden-runner@",
        }
        self.assertEqual(set(jobs), set(actions))
        for job, action in actions.items():
            with self.subTest(job=job):
                self.assertIn(action, jobs[job])
                for other in set(actions.values()) - {action}:
                    self.assertNotIn(other, jobs[job])
        self.assertIn("nodejs.org:443", jobs["stepsecurity-build"])


if __name__ == "__main__":
    unittest.main()
