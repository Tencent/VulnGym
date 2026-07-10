from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path

from tools.trace_cleanup import load_jsonl, process_entries, validate_entries


ROOT = Path(__file__).resolve().parent.parent
SOURCE_PATH = ROOT / "data" / "entries.jsonl"
FIXED_PATH = ROOT / "data" / "entries.trace_fixed.jsonl"
REPORTS_PATH = ROOT / "data" / "reports.jsonl"
LOG_PATH = ROOT / "trace_fix_log.csv"
REPORT_PATH = ROOT / "trace_cleanup_report.json"


class GeneratedArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = load_jsonl(SOURCE_PATH)
        cls.fixed = load_jsonl(FIXED_PATH)
        cls.reports = load_jsonl(REPORTS_PATH)
        with LOG_PATH.open(encoding="utf-8", newline="") as handle:
            cls.log_rows = list(csv.DictReader(handle))
        cls.report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    def test_fixed_artifact_is_reproducible(self):
        regenerated, findings, summary = process_entries(self.source, mode="fix")
        self.assertEqual(regenerated, self.fixed)
        self.assertEqual(len(findings), len(self.log_rows))
        self.assertEqual(summary, self.report["summary"])

    def test_fixed_artifact_preserves_schema_rows_ids_and_non_trace_fields(self):
        validate_entries(self.fixed)
        self.assertEqual(408, len(self.fixed))
        self.assertEqual(
            [item["entry_id"] for item in self.source],
            [item["entry_id"] for item in self.fixed],
        )

        for before, after in zip(self.source, self.fixed):
            before_without_trace = {key: value for key, value in before.items() if key != "trace"}
            after_without_trace = {key: value for key, value in after.items() if key != "trace"}
            self.assertEqual(before_without_trace, after_without_trace)

    def test_trace_nodes_are_only_removed_and_never_reordered(self):
        for before, after in zip(self.source, self.fixed):
            original = before["trace"]
            cursor = 0
            for node in after["trace"]:
                while cursor < len(original) and original[cursor] != node:
                    cursor += 1
                self.assertLess(
                    cursor,
                    len(original),
                    f"{before['entry_id']} output trace is not an ordered subsequence",
                )
                cursor += 1

    def test_report_entry_join_invariants_are_preserved(self):
        report_by_id = {report["report_id"]: report for report in self.reports}
        grouped_entry_ids: dict[str, list[str]] = {}
        for item in self.fixed:
            grouped_entry_ids.setdefault(item["report_id"], []).append(item["entry_id"])
            self.assertIn(item["report_id"], report_by_id)

        self.assertEqual(set(report_by_id), set(grouped_entry_ids))
        for report_id, report in report_by_id.items():
            expected_ids = sorted(grouped_entry_ids[report_id])
            self.assertEqual(expected_ids, report["entry_ids"])
            self.assertEqual(len(expected_ids), report["num_entries"])

    def test_priority_samples_have_expected_fix_or_review(self):
        removals = {
            (row["entry_id"], row["field_path"], row["finding"])
            for row in self.log_rows
            if row["action"] == "remove"
        }
        self.assertEqual(
            {
                ("entry-00103", "trace[1]", "trace_before_entry_point"),
                ("entry-00185", "trace[2]", "trace_after_critical_operation"),
                ("entry-00320", "trace[2]", "trace_before_entry_point"),
                ("entry-00511", "trace[4]", "trace_after_critical_operation"),
            },
            removals,
        )

        issue_511_reviews = {
            (row["field_path"], row["finding"], row["action"])
            for row in self.log_rows
            if row["entry_id"] == "entry-00511"
        }
        self.assertIn(
            ("trace[0]", "trace_before_entry_point", "manual_review"),
            issue_511_reviews,
        )
        self.assertIn(
            ("trace[5]", "trace_after_critical_operation", "manual_review"),
            issue_511_reviews,
        )

    def test_report_records_full_scan_and_schema_success(self):
        self.assertEqual("fix", self.report["mode"])
        self.assertTrue(self.report["schema_validation"]["passed"])
        self.assertEqual(408, self.report["summary"]["entries_scanned"])
        self.assertEqual(2073, self.report["summary"]["trace_nodes_scanned"])
        self.assertEqual(4, self.report["summary"]["auto_fixes"])
        self.assertEqual(4, self.report["summary"]["entries_modified"])


if __name__ == "__main__":
    unittest.main()
