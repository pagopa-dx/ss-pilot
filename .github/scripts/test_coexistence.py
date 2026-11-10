import json
from pathlib import Path
import re
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


class HarnessPinTests(unittest.TestCase):
    def test_harness_uses_the_same_immutable_action_snapshots(self):
        root = Path(__file__).resolve().parents[2]
        pattern = r"pagopa-dx/ss-pilot/\.github/actions/{}@([0-9a-f]{{40}})"

        def pins(path, action):
            return re.findall(pattern.format(action), (root / path).read_text())

        smoke = pins(".github/workflows/combined-runtime-pilot.yml", "combined-runtime")
        harness = pins(".github/workflows/runtime-coexistence.yml", "combined-runtime")
        self.assertEqual(len(smoke), 1)
        self.assertTrue(harness)
        self.assertEqual(set(harness), set(smoke))

        composite = pins(".github/actions/combined-runtime/action.yml", "falco-lifecycle")
        control = pins(".github/actions/falco-pilot-start/action.yml", "falco-lifecycle")
        self.assertEqual(len(composite), 1)
        self.assertEqual(control, composite)


if __name__ == "__main__":
    unittest.main()
