import json
import unittest

from coexistence_verify import marker_event


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


if __name__ == "__main__":
    unittest.main()
