#!/usr/bin/env python3
"""Require complete, skip-free E2E coverage from the Go JSON event stream."""

import argparse
import json
from pathlib import Path
import sys


def load_matrix(path):
    matrix = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(matrix, dict) or not isinstance(matrix.get("package"), str) or not matrix["package"]:
        raise ValueError("matrix must name the Go package")
    flows = matrix.get("flows")
    if not isinstance(flows, list) or not flows:
        raise ValueError("matrix must contain required flows")
    seen = set()
    for flow in flows:
        if not isinstance(flow, dict) or not isinstance(flow.get("name"), str):
            raise ValueError("each flow must have a name")
        tests = flow.get("tests")
        if not isinstance(tests, list) or not tests:
            raise ValueError(f"flow {flow['name']} must contain tests")
        for test in tests:
            if not isinstance(test, str) or not test.startswith("Test") or test in seen:
                raise ValueError(f"invalid or duplicate required test: {test!r}")
            seen.add(test)
    return matrix


def evaluate(events, matrix):
    """Consume events incrementally; retain only test/package outcomes."""
    errors = []
    tests = {}
    packages = {}
    skipped = []
    failed = []
    for line_number, line in enumerate(events, 1):
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("event must be an object")
            action = event.get("Action")
            # Go 1.24+ interleaves build events, whose package field is
            # ImportPath rather than the TestEvent Package field.
            package = event.get("ImportPath" if action in ("build-output", "build-fail") else "Package")
            test = event.get("Test")
            if not isinstance(action, str) or not isinstance(package, str) or not package:
                raise ValueError("event must have Action and Package strings")
            if test is not None and (not isinstance(test, str) or not test):
                raise ValueError("Test must be a nonempty string")
        except (ValueError, TypeError) as exc:
            errors.append(f"line {line_number}: invalid Go test event: {exc}")
            continue

        if test:
            key = (package, test)
            if action == "run":
                if key in tests:
                    errors.append(f"duplicate test run: {package}/{test}")
                tests[key] = "running"
            elif action in ("pass", "skip", "fail"):
                if tests.get(key) != "running":
                    errors.append(f"test {action} without an active run: {package}/{test}")
                tests[key] = action
        elif action == "start":
            if package in packages:
                errors.append(f"duplicate package run: {package}")
            packages[package] = "running"
        elif action in ("pass", "skip", "fail"):
            if packages.get(package) != "running":
                errors.append(f"package {action} without an active run: {package}")
            packages[package] = action

        label = f"{package}/{test}" if test else package
        if action == "skip":
            skipped.append(label)
        elif action in ("fail", "build-fail"):
            failed.append(label)

    package = matrix["package"]
    flows = []
    for flow in matrix["flows"]:
        outcomes = {test: tests.get((package, test), "missing") for test in flow["tests"]}
        flows.append({"name": flow["name"], "passed": all(v == "pass" for v in outcomes.values()), "tests": outcomes})
    incomplete = [f"{pkg}/{test}" for (pkg, test), status in tests.items() if status == "running"]
    incomplete.extend(pkg for pkg, status in packages.items() if status == "running")
    if packages.get(package) != "pass":
        errors.append(f"required package did not pass: {package}")
    passed = sum(flow["passed"] for flow in flows)
    return {
        "ok": passed == len(flows) and not (errors or skipped or failed or incomplete),
        "passed_flows": passed,
        "required_flows": len(flows),
        "flows": flows,
        "skipped": skipped,
        "failed": failed,
        "incomplete": incomplete,
        "errors": errors,
    }


def markdown(report):
    lines = ["## Required E2E coverage", "", summary(report), "", "| Flow | Result |", "| --- | --- |"]
    for flow in report["flows"]:
        status = "PASS" if flow["passed"] else ", ".join(
            f"{test}: {outcome}" for test, outcome in flow["tests"].items() if outcome != "pass"
        )
        lines.append(f"| {flow['name']} | {status} |")
    for kind in ("skipped", "failed", "incomplete", "errors"):
        if report[kind]:
            lines.extend(["", f"{kind.capitalize()}:", ""])
            lines.extend(f"- {item}" for item in report[kind])
    return "\n".join(lines) + "\n"


def summary(report):
    return (
        f"E2E coverage: {report['passed_flows']}/{report['required_flows']} required flows passed; "
        f"skipped={len(report['skipped'])}; failed={len(report['failed'])}; "
        f"incomplete={len(report['incomplete'])}; errors={len(report['errors'])}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="go test -json event stream")
    parser.add_argument("--matrix", type=Path, default=Path(__file__).with_name("required_flows.json"))
    parser.add_argument("--report", required=True, type=Path, help="write machine-readable coverage report")
    parser.add_argument("--summary", type=Path, help="append Markdown coverage to GitHub step summary")
    args = parser.parse_args()
    try:
        matrix = load_matrix(args.matrix)
        with args.input.open(encoding="utf-8") as events:
            report = evaluate(events, matrix)
    except (OSError, ValueError) as exc:
        report = {"ok": False, "passed_flows": 0, "required_flows": 0, "flows": [],
                  "skipped": [], "failed": [], "incomplete": [], "errors": [str(exc)]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(summary(report))
    for error in report["errors"]:
        print(error, file=sys.stderr)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as output:
            output.write(markdown(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
