"""Regression tests for the CI coverage gate; no network or third-party modules."""

import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import check_report


PACKAGE = "example.com/artigate/e2e"
MATRIX = {"package": PACKAGE, "flows": [{"name": "Consumer", "tests": ["TestConsumer"]}]}


def event(action, test=None, **extra):
    value = {"Action": action, "Package": PACKAGE, **extra}
    if test:
        value["Test"] = test
    return json.dumps(value) + "\n"


def passing_events():
    return event("start") + event("run", "TestConsumer") + event("pass", "TestConsumer") + event("pass")


class CoverageReportTests(unittest.TestCase):
    def check_events(self, events):
        return check_report.evaluate(io.StringIO(events), MATRIX)

    def test_complete_run_passes(self):
        report = self.check_events(passing_events())
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["passed_flows"], 1)

    def test_skipped_subtest_cannot_hide_in_passing_parent(self):
        events = event("start") + event("run", "TestConsumer")
        events += event("run", "TestConsumer/optional") + event("skip", "TestConsumer/optional")
        events += event("pass", "TestConsumer") + event("pass")
        report = self.check_events(events)
        self.assertFalse(report["ok"])
        self.assertEqual(report["passed_flows"], 1)
        self.assertEqual(report["skipped"], [PACKAGE + "/TestConsumer/optional"])

    def test_missing_required_flow_rejected_even_when_package_passes(self):
        report = self.check_events(event("start") + event("pass"))
        self.assertFalse(report["ok"])
        self.assertEqual(report["flows"][0]["tests"]["TestConsumer"], "missing")

    def test_failure_elsewhere_rejected(self):
        events = passing_events().removesuffix(event("pass"))
        events += event("run", "TestExtra") + event("fail", "TestExtra") + event("fail")
        report = self.check_events(events)
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["failed"]), 2)

    def test_truncated_or_empty_stream_rejected(self):
        for events in ("", event("start"), event("start") + event("run", "TestConsumer"),
                       passing_events().removesuffix(event("pass"))):
            with self.subTest(events=events):
                self.assertFalse(self.check_events(events)["ok"])

    def test_invalid_json_and_invalid_event_rejected(self):
        for bad in ("not-json\n", "{\n", "[]\n", "{}\n", '{"Action": "pass", "Package": 12}\n'):
            with self.subTest(bad=bad):
                report = self.check_events(passing_events() + bad)
                self.assertFalse(report["ok"])
                self.assertTrue(report["errors"])

    def test_output_text_is_not_a_skip_event(self):
        events = passing_events() + event("output", Output="--- SKIP: upstream documentation example\n")
        self.assertTrue(self.check_events(events)["ok"])

    def test_build_events_use_import_path_and_build_failures_reject(self):
        build = json.dumps({"Action": "build-output", "ImportPath": PACKAGE, "Output": "compiler warning\n"}) + "\n"
        self.assertTrue(self.check_events(build + passing_events())["ok"])
        failure = json.dumps({"Action": "build-fail", "ImportPath": PACKAGE}) + "\n"
        report = self.check_events(build + failure + passing_events())
        self.assertFalse(report["ok"])
        self.assertEqual(report["failed"], [PACKAGE])

    def test_wrong_package_does_not_satisfy_matrix(self):
        self.assertFalse(self.check_events(passing_events().replace(PACKAGE, "another/package"))["ok"])

    def test_terminal_event_requires_run_and_repeated_run_rejected(self):
        for events in (event("start") + event("pass", "TestConsumer") + event("pass"),
                       passing_events() + passing_events()):
            with self.subTest(events=events):
                self.assertFalse(self.check_events(events)["ok"])

    def test_matrix_names_all_current_top_level_tests(self):
        directory = Path(__file__).parent
        matrix = check_report.load_matrix(directory / "required_flows.json")
        required = {test for flow in matrix["flows"] for test in flow["tests"] if "/" not in test}
        declared = set()
        for source in directory.glob("*_test.go"):
            declared.update(re.findall(r"^func (Test\w+)\(t \*testing.T\)", source.read_text(), re.MULTILINE))
        self.assertEqual(required, declared, "update required_flows.json when adding or renaming E2E tests")

    def test_missing_input_creates_failed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            process = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("check_report.py")),
                 "--input", str(Path(directory) / "missing.jsonl"), "--report", str(report)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 1)
            self.assertFalse(json.loads(report.read_text())["ok"])


if __name__ == "__main__":
    unittest.main()
