import sys
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import trace_structure_cleanup


def make_entry(trace, *, verify=0, entry_line=10, critical_line=100):
    return {
        "entry_id": "entry-test",
        "report_id": "GHSA-TEST-0000-0000",
        "source_link": "https://github.com/advisories/GHSA-test-0000-0000",
        "vuln_ids": ["GHSA-TEST-0000-0000"],
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "demo",
        "repo_url": "https://github.com/example/demo",
        "commit": "a" * 40,
        "vuln_title": "demo vulnerability",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "verify": verify,
        "entry_point": {"file": "same.py", "line": entry_line, "code": "entry"},
        "critical_operation": {"file": "same.py", "line": critical_line, "code": "sink"},
        "trace": trace,
    }


def process(entry, argv):
    args = trace_structure_cleanup.parse_args(argv)
    logs = []
    stats = Counter()
    fixed = trace_structure_cleanup.process_entry(entry, logs, stats, args)
    return fixed, logs, stats


class TraceStructureCleanupTests(unittest.TestCase):
    def test_parse_line_span_accepts_int_and_range(self):
        self.assertEqual(trace_structure_cleanup.parse_line_span(12).start, 12)
        self.assertEqual(trace_structure_cleanup.parse_line_span("12").end, 12)
        span = trace_structure_cleanup.parse_line_span("12-15")
        self.assertEqual((span.start, span.end), (12, 15))
        self.assertIsNone(trace_structure_cleanup.parse_line_span("15-12"))
        self.assertIsNone(trace_structure_cleanup.parse_line_span(0))

    def test_check_mode_reports_duplicate_without_changing_trace(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "same"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "same"},
            ]
        )

        fixed, logs, stats = process(entry, ["--mode", "check"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(stats["duplicate_nodes"], 1)
        self.assertEqual(logs[0]["issue_type"], "duplicate_node")
        self.assertEqual(logs[0]["action"], "manual_review")

    def test_fix_mode_removes_safe_duplicate_for_target_verify_bucket(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "same"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "same"},
            ]
        )

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], [entry["trace"][0]])
        self.assertEqual(logs[0]["action"], "removed")

    def test_safe_duplicate_policy_keeps_conflicting_desc(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "first"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "second"},
            ]
        )

        fixed, logs, stats = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(stats["duplicate_desc_conflicts"], 1)
        self.assertEqual(logs[0]["action"], "manual_review")

    def test_drop_all_duplicate_policy_removes_conflicting_desc(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "first"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "second"},
            ]
        )

        fixed, logs, _ = process(entry, ["--mode", "fix", "--duplicate-policy", "drop-all"])

        self.assertEqual(fixed["trace"], [entry["trace"][0]])
        self.assertEqual(logs[0]["action"], "removed")

    def test_non_target_verify_bucket_is_not_changed(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup"},
                {"file": "same.py", "line": 50, "code": "dup"},
            ],
            verify=1,
        )

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(logs[0]["action"], "skipped_not_fix_target")

    def test_before_entry_range_is_removed_when_wholly_before_entry(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": "3-8", "code": "before"},
                {"file": "same.py", "line": "10-12", "code": "keep"},
            ]
        )

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], [entry["trace"][1]])
        self.assertEqual(logs[0]["issue_type"], "order_before_entry")
        self.assertEqual(logs[0]["action"], "removed")

    def test_before_entry_overlap_is_manual_review(self):
        entry = make_entry([{"file": "same.py", "line": "8-12", "code": "overlap"}])

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(logs[0]["issue_type"], "order_before_entry_overlap")
        self.assertEqual(logs[0]["action"], "manual_review")

    def test_after_critical_default_policy_keeps_node_for_review(self):
        entry = make_entry([{"file": "same.py", "line": 120, "code": "after"}])

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(logs[0]["issue_type"], "order_after_critical")
        self.assertEqual(logs[0]["action"], "manual_review")

    def test_after_critical_bounds_policy_removes_node(self):
        entry = make_entry([{"file": "same.py", "line": 120, "code": "after"}])

        fixed, logs, _ = process(entry, ["--mode", "fix", "--order-policy", "bounds"])

        self.assertEqual(fixed["trace"], [])
        self.assertEqual(logs[0]["action"], "removed")

    def test_cross_file_node_is_not_reordered_or_changed(self):
        entry = make_entry([{"file": "other.py", "line": 1, "code": "cross"}])

        fixed, logs, stats = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(logs, [])
        self.assertEqual(stats["cross_file_entry_comparisons_skipped"], 1)
        self.assertEqual(stats["cross_file_critical_comparisons_skipped"], 1)

    def test_validate_entries_accepts_minimal_valid_entry(self):
        entry = make_entry([{"file": "same.py", "line": "10-12", "code": "trace"}])

        self.assertEqual(trace_structure_cleanup.validate_entries([entry]), [])


if __name__ == "__main__":
    unittest.main()
