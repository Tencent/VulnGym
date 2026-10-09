from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_trace_regressions import (
    TraceDataError,
    compare_jsonl_texts,
    comparison_to_dict,
    main,
    parse_line_span,
)


def node(file: str, line: int | str, code: str, desc: str = "") -> dict:
    value = {"file": file, "line": line, "code": code}
    if desc:
        value["desc"] = desc
    return value


def entry(entry_id: str, trace: list[dict]) -> dict:
    return {
        "entry_id": entry_id,
        "entry_point": node("app.py", 10, "entry()"),
        "critical_operation": node("app.py", 20, "sink()"),
        "trace": trace,
    }


def jsonl(*entries: dict) -> str:
    return "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in entries)


class TraceRegressionGateTests(unittest.TestCase):
    def test_legacy_findings_do_not_fail_an_unchanged_candidate(self) -> None:
        legacy = entry(
            "entry-00001",
            [
                node("app.py", 5, "before()"),
                node("app.py", 15, "same()"),
                node("app.py", 15, "same()", "different description"),
                node("app.py", 25, "after()"),
            ],
        )
        comparison = compare_jsonl_texts(jsonl(legacy), jsonl(legacy))

        self.assertEqual(comparison.new_findings, [])
        self.assertEqual(comparison.resolved_findings, [])
        self.assertEqual(comparison.unchanged_finding_count, 3)

    def test_only_the_new_duplicate_occurrence_is_a_regression(self) -> None:
        repeated = node("app.py", 15, "step()")
        baseline = entry("entry-00001", [repeated, repeated])
        candidate = entry("entry-00001", [repeated, repeated, repeated])

        comparison = compare_jsonl_texts(jsonl(baseline), jsonl(candidate))

        self.assertEqual(len(comparison.new_findings), 1)
        finding = comparison.new_findings[0]
        self.assertEqual(finding.kind, "duplicate")
        self.assertEqual(finding.occurrence, 2)

    def test_new_before_entry_and_after_critical_nodes_are_regressions(self) -> None:
        baseline = entry("entry-00001", [node("app.py", 15, "valid()")])
        candidate = entry(
            "entry-00001",
            [
                node("app.py", 5, "before()"),
                node("app.py", 15, "valid()"),
                node("app.py", 25, "after()"),
            ],
        )

        comparison = compare_jsonl_texts(jsonl(baseline), jsonl(candidate))

        self.assertEqual(
            {finding.kind for finding in comparison.new_findings},
            {"before_entry", "after_critical"},
        )

    def test_ranges_that_overlap_anchors_and_cross_file_nodes_are_safe(self) -> None:
        value = entry(
            "entry-00001",
            [
                node("app.py", "8-12", "overlaps entry"),
                node("app.py", "18-22", "overlaps critical"),
                node("other.py", 1, "cross-file early"),
                node("other.py", 100, "cross-file late"),
            ],
        )

        comparison = compare_jsonl_texts(jsonl(value), jsonl(value))

        self.assertEqual(comparison.candidate.findings, [])
        self.assertEqual(comparison.candidate.skipped_cross_file_comparisons, 4)

    def test_desc_changes_and_index_reordering_do_not_create_regressions(self) -> None:
        first = node("app.py", 15, "same()", "old")
        duplicate = node("app.py", 15, "same()", "conflicting")
        other = node("app.py", 16, "other()")
        baseline = entry("entry-00001", [first, duplicate, other])
        candidate = entry(
            "entry-00001",
            [other, node("app.py", 15, "same()", "new"), duplicate],
        )

        comparison = compare_jsonl_texts(jsonl(baseline), jsonl(candidate))

        self.assertEqual(comparison.new_findings, [])
        self.assertEqual(comparison.resolved_findings, [])

    def test_resolving_a_finding_never_fails_the_gate(self) -> None:
        baseline = entry("entry-00001", [node("app.py", 5, "before()")])
        candidate = entry("entry-00001", [node("app.py", 15, "valid()")])

        comparison = compare_jsonl_texts(jsonl(baseline), jsonl(candidate))

        self.assertEqual(comparison.new_findings, [])
        self.assertEqual(len(comparison.resolved_findings), 1)

    def test_findings_in_a_new_entry_are_reported(self) -> None:
        baseline = entry("entry-00001", [node("app.py", 15, "valid()")])
        added = entry("entry-00002", [node("app.py", 5, "new before()")])

        comparison = compare_jsonl_texts(
            jsonl(baseline),
            jsonl(baseline, added),
        )

        self.assertEqual(len(comparison.new_findings), 1)
        self.assertEqual(comparison.new_findings[0].entry_id, "entry-00002")

    def test_line_parser_rejects_unsafe_or_malformed_values(self) -> None:
        self.assertEqual(parse_line_span(7, "node"), (7, 7))
        self.assertEqual(parse_line_span("7-9", "node"), (7, 9))
        for invalid in (True, 0, "0-1", "9-7", "7", "x-y"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TraceDataError):
                    parse_line_span(invalid, "node")

    def test_cli_writes_deterministic_reports_and_uses_exit_code_one(self) -> None:
        baseline = jsonl(entry("entry-00001", [node("app.py", 15, "step()")]))
        candidate = jsonl(
            entry(
                "entry-00001",
                [node("app.py", 15, "step()"), node("app.py", 15, "step()")],
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline_path = root / "baseline.jsonl"
            candidate_path = root / "candidate.jsonl"
            json_path = root / "report.json"
            markdown_path = root / "report.md"
            baseline_path.write_text(baseline, encoding="utf-8")
            candidate_path.write_text(candidate, encoding="utf-8")
            args = [
                "--baseline",
                str(baseline_path),
                "--candidate",
                str(candidate_path),
                "--json-report",
                str(json_path),
                "--markdown-report",
                str(markdown_path),
            ]

            with contextlib.redirect_stdout(io.StringIO()):
                first_exit = main(args)
            first_json = json_path.read_bytes()
            first_markdown = markdown_path.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                second_exit = main(args)

            self.assertEqual(first_exit, 1)
            self.assertEqual(second_exit, 1)
            self.assertEqual(first_json, json_path.read_bytes())
            self.assertEqual(first_markdown, markdown_path.read_bytes())
            payload = json.loads(first_json)
            self.assertEqual(payload["comparison"]["new_finding_count"], 1)
            self.assertEqual(payload["comparison"]["result"], "fail")

    def test_cli_returns_exit_code_two_for_non_utf8_input(self) -> None:
        baseline = jsonl(entry("entry-00001", []))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline_path = root / "baseline.jsonl"
            candidate_path = root / "candidate.jsonl"
            baseline_path.write_text(baseline, encoding="utf-8")
            candidate_path.write_bytes(b"\xff\xfe")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "--baseline",
                        str(baseline_path),
                        "--candidate",
                        str(candidate_path),
                    ]
                )

            self.assertEqual(exit_code, 2)
            self.assertIn("not valid UTF-8", stderr.getvalue())

    def test_report_order_is_stable_across_entry_order(self) -> None:
        first = entry("entry-00001", [node("app.py", 5, "first()")])
        second = entry("entry-00002", [node("app.py", 25, "second()")])
        baseline = jsonl(entry("entry-00001", []), entry("entry-00002", []))

        forward = comparison_to_dict(
            compare_jsonl_texts(baseline, jsonl(first, second))
        )
        reverse = comparison_to_dict(
            compare_jsonl_texts(baseline, jsonl(second, first))
        )

        self.assertEqual(
            forward["comparison"]["new_findings"],
            reverse["comparison"]["new_findings"],
        )


if __name__ == "__main__":
    unittest.main()
