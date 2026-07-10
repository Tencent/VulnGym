from __future__ import annotations

import copy
import csv
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tools.trace_cleanup import (
    SchemaError,
    load_jsonl,
    main,
    parse_line_span,
    process_entries,
    validate_entries,
)


def node(file: str, line, code: str, desc: str | None = None):
    value = {"file": file, "line": line, "code": code}
    if desc is not None:
        value["desc"] = desc
    return value


def entry(
    trace,
    *,
    entry_point=None,
    critical_operation=None,
    verify: int = 0,
):
    return {
        "commit": "a" * 40,
        "critical_operation": critical_operation or node("same.py", 20, "sink()"),
        "entry_id": "entry-00001",
        "entry_point": entry_point or node("same.py", 10, "source()"),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "example",
        "repo_url": "https://github.com/example/example",
        "report_id": "GHSA-2345-6789-CFGH",
        "source_link": "https://github.com/advisories/GHSA-2345-6789-cfgh",
        "trace": trace,
        "verify": verify,
        "vuln_category_l1": "Example",
        "vuln_category_l2": "Example detail",
        "vuln_ids": ["GHSA-2345-6789-CFGH"],
        "vuln_title": "Example vulnerability",
    }


class LineSpanTests(unittest.TestCase):
    def test_integer_and_range_are_normalized(self):
        self.assertEqual((7, 7), tuple(vars(parse_line_span(7)).values()))
        self.assertEqual((7, 12), tuple(vars(parse_line_span("7-12")).values()))

    def test_invalid_line_values_are_rejected(self):
        for value in (0, -1, True, "0-1", "8-7", "7", " 7-8 ", None):
            with self.subTest(value=value), self.assertRaises(SchemaError):
                parse_line_span(value)


class TraceProcessingTests(unittest.TestCase):
    def test_exact_duplicate_is_removed_and_missing_description_is_synced(self):
        first = node("same.py", 12, "step()")
        duplicate = node("same.py", 12, "step()", "useful explanation")
        output, findings, summary = process_entries(
            [entry([first, duplicate])], mode="fix"
        )

        self.assertEqual(1, len(output[0]["trace"]))
        self.assertEqual("useful explanation", output[0]["trace"][0]["desc"])
        self.assertEqual(1, summary["duplicate_candidates"])
        self.assertEqual(1, summary["duplicate_nodes_removed"])
        self.assertEqual(1, summary["descriptions_synced"])
        self.assertEqual(
            {"duplicate_node", "duplicate_description_sync"},
            {item.finding for item in findings if item.finding.startswith("duplicate")},
        )

    def test_conflicting_duplicate_descriptions_keep_first_and_require_review(self):
        first = node("same.py", 12, "step()", "first explanation")
        duplicate = node("same.py", 12, "step()", "different explanation")
        output, findings, summary = process_entries(
            [entry([first, duplicate])], mode="fix"
        )

        self.assertEqual("first explanation", output[0]["trace"][0]["desc"])
        self.assertEqual(1, summary["description_conflicts"])
        conflicts = [
            item for item in findings if item.finding == "duplicate_description_conflict"
        ]
        self.assertEqual("manual_review", conflicts[0].action)

    def test_report_mode_never_changes_input(self):
        original = entry(
            [
                node("same.py", 5, "early()"),
                node("same.py", 12, "repeat()"),
                node("same.py", 12, "repeat()"),
            ]
        )
        expected = copy.deepcopy(original)
        output, _, summary = process_entries([original], mode="report")

        self.assertEqual([expected], output)
        self.assertEqual(0, summary["auto_fixes"])
        self.assertGreater(summary["reported_findings"], 0)

    def test_fix_removes_only_wholly_outside_same_file_ranges(self):
        trace = [
            node("same.py", 5, "early()"),
            node("same.py", "9-10", "entry_overlap()"),
            node("same.py", 10, "entry_boundary()"),
            node("same.py", "20-21", "critical_overlap()"),
            node("same.py", 25, "late()"),
            node("other.py", 1, "cross_file()"),
        ]
        output, findings, summary = process_entries([entry(trace)], mode="fix")

        self.assertEqual(
            ["entry_overlap()", "entry_boundary()", "critical_overlap()", "cross_file()"],
            [item["code"] for item in output[0]["trace"]],
        )
        self.assertEqual(2, summary["out_of_bounds_nodes_removed"])
        self.assertEqual(1, summary["entry_boundary_overlaps"])
        self.assertEqual(1, summary["critical_boundary_overlaps"])
        self.assertTrue(
            any(item.finding == "cross_file_comparison_skipped" for item in findings)
        )
        self.assertTrue(
            all(
                item.action == "manual_review"
                for item in findings
                if "overlap" in item.reason
            )
        )

    def test_cross_file_nodes_are_never_sorted_or_removed(self):
        trace = [
            node("z.py", 900, "first_cross_file()"),
            node("a.py", 1, "second_cross_file()"),
        ]
        output, _, summary = process_entries([entry(trace)], mode="fix")

        self.assertEqual(trace, output[0]["trace"])
        self.assertEqual(2, summary["cross_file_nodes"])
        self.assertEqual(4, summary["cross_file_comparisons_skipped"])

    def test_verified_entries_are_report_only_without_explicit_opt_in(self):
        source = entry([node("same.py", 5, "early()")], verify=1)
        output, findings, summary = process_entries([source], mode="fix")

        self.assertEqual(source, output[0])
        self.assertEqual(0, summary["auto_fixes"])
        anomaly = next(
            item for item in findings if item.finding == "trace_before_entry_point"
        )
        self.assertEqual("manual_review", anomaly.action)

    def test_include_verified_allows_deterministic_fix(self):
        output, _, summary = process_entries(
            [entry([node("same.py", 5, "early()")], verify=1)],
            mode="fix",
            include_verified=True,
        )
        self.assertEqual([], output[0]["trace"])
        self.assertEqual(1, summary["auto_fixes"])

    def test_endpoint_repetition_is_not_a_trace_duplicate(self):
        source = entry(
            [node("same.py", 10, "source()"), node("same.py", 20, "sink()")]
        )
        _, _, summary = process_entries([source], mode="report")
        self.assertEqual(0, summary["duplicate_candidates"])


class SchemaAndCliTests(unittest.TestCase):
    def test_basic_schema_validation(self):
        valid = entry([])
        validate_entries([valid])

        invalid = copy.deepcopy(valid)
        invalid["trace"] = [node("same.py", "0-4", "bad()")]
        with self.assertRaises(SchemaError):
            validate_entries([invalid])

    def test_cli_writes_jsonl_csv_and_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "entries.jsonl"
            output_path = root / "entries.fixed.jsonl"
            log_path = root / "trace_fix_log.csv"
            report_path = root / "trace_cleanup_report.json"
            input_path.write_text(
                json.dumps(entry([node("same.py", 5, "early()")]), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(output_path),
                        "--log",
                        str(log_path),
                        "--report",
                        str(report_path),
                        "--mode",
                        "fix",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual([], load_jsonl(output_path)[0]["trace"])
            with log_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual("trace[0]", rows[0]["field_path"])
            self.assertEqual("remove", rows[0]["action"])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["schema_validation"]["passed"])
            self.assertEqual(1, report["summary"]["out_of_bounds_nodes_removed"])
            self.assertIn("output_sha256", report)

    def test_cli_report_mode_keeps_jsonl_byte_identical(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "entries.jsonl"
            output_path = root / "entries.reported.jsonl"
            payload = json.dumps(
                entry([node("same.py", 5, "early()")]),
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8") + b"\r\n"
            input_path.write_bytes(payload)

            with redirect_stdout(io.StringIO()):
                main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(output_path),
                        "--log",
                        str(root / "log.csv"),
                        "--report",
                        str(root / "report.json"),
                    ]
                )

            self.assertEqual(payload, output_path.read_bytes())

    def test_default_report_names_do_not_overlap_fix_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data_dir = root / "data"
            data_dir.mkdir()
            input_path = data_dir / "entries.jsonl"
            input_path.write_text(
                json.dumps(entry([]), sort_keys=True) + "\n", encoding="utf-8"
            )
            previous_cwd = Path.cwd()
            try:
                os.chdir(root)
                with redirect_stdout(io.StringIO()):
                    main([])
            finally:
                os.chdir(previous_cwd)

            self.assertTrue((data_dir / "entries.trace_reported.jsonl").is_file())
            self.assertTrue((root / "trace_report_log.csv").is_file())
            self.assertTrue((root / "trace_report.json").is_file())
            self.assertFalse((data_dir / "entries.trace_fixed.jsonl").exists())
            self.assertFalse((root / "trace_fix_log.csv").exists())
            self.assertFalse((root / "trace_cleanup_report.json").exists())


if __name__ == "__main__":
    unittest.main()
