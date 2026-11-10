import json
from pathlib import Path
import tempfile
import unittest

from coexistence_verify import marker_event, verify_build


class FalcoMarkerTests(unittest.TestCase):
    def test_requires_matching_rule_and_process(self):
        events = "\n".join(json.dumps(item) for item in [
            {"rule": "Other", "output_fields": {"proc.pid": 101}},
            {"rule": "SS Pilot Controlled Process Marker", "output_fields": {"proc.pid": 102}},
        ])
        self.assertIsNone(marker_event(events, 101))
        self.assertEqual(marker_event(events, 102)["rule"], "SS Pilot Controlled Process Marker")

    def test_does_not_hide_malformed_native_events(self):
        with self.assertRaises(json.JSONDecodeError):
            marker_event("not-json", 123)


class BuildEvidenceTests(unittest.TestCase):
    def test_requires_all_build_phases_and_the_expected_hook_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = {stage: "success" for stage in (
                "install", "lint", "typecheck", "test", "build", "smoke"
            )}
            (root / "build.json").write_text(json.dumps(build))
            hook = {"domain": "example.com", "exit_code": 0, "http_status": 200}
            (root / "hook.json").write_text(json.dumps(hook))
            self.assertEqual(verify_build(root, "audit")["hook"], hook)
            with self.assertRaisesRegex(ValueError, "not rejected"):
                verify_build(root, "block")

            hook.update(exit_code=1, error_code="EAI_AGAIN")
            (root / "hook.json").write_text(json.dumps(hook))
            self.assertEqual(verify_build(root, "block")["hook"], hook)
            with self.assertRaisesRegex(ValueError, "did not succeed"):
                verify_build(root, "audit")

            build["lint"] = "failure"
            (root / "build.json").write_text(json.dumps(build))
            with self.assertRaisesRegex(ValueError, "lint"):
                verify_build(root, "block")


if __name__ == "__main__":
    unittest.main()
