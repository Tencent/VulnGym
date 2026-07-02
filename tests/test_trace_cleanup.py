import sys
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import trace_cleanup


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
        "vuln_title": "demo vuln",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "verify": verify,
        "entry_point": {
            "file": "same.py",
            "line": entry_line,
            "code": "entry",
            "desc": "entry",
        },
        "critical_operation": {
            "file": "same.py",
            "line": critical_line,
            "code": "critical",
            "desc": "critical",
        },
        "trace": trace,
    }


def process(entry, argv):
    args = trace_cleanup.parse_args(argv)
    logs = []
    stats = Counter()
    fixed = trace_cleanup.process_entry(entry, logs, stats, args)
    return fixed, logs, stats


class TraceCleanupTests(unittest.TestCase):
    def test_default_reports_are_written_under_reports(self):
        args = trace_cleanup.parse_args([])

        self.assertEqual(args.log_out, ROOT / "reports" / "trace_fix_log.json")
        self.assertEqual(args.report_out, ROOT / "reports" / "trace_fix_report.json")
        self.assertEqual(args.report_md_out, ROOT / "reports" / "trace_fix_report.md")

    def test_report_uses_repo_relative_paths_for_default_files(self):
        args = trace_cleanup.parse_args(["--mode", "fix"])
        entry = make_entry([])

        report = trace_cleanup.build_report(
            input_path=ROOT / "data" / "entries.jsonl",
            output_path=ROOT / "data" / "entries.trace_fixed.jsonl",
            original_rows=[entry],
            fixed_rows=[entry],
            logs=[],
            stats=Counter(),
            args=args,
        )

        self.assertEqual(report["config"]["input"], "data/entries.jsonl")
        self.assertEqual(report["config"]["output"], "data/entries.trace_fixed.jsonl")

    def test_safe_duplicate_policy_keeps_conflicting_desc(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "first"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "second"},
            ]
        )

        fixed, logs, stats = process(entry, ["--mode", "fix", "--fix-verify", "all"])

        self.assertEqual(fixed["trace"], entry["trace"])
        self.assertEqual(stats["duplicate_desc_conflicts"], 1)
        duplicate_log = [log for log in logs if log["event_type"] == "duplicate_node"][0]
        self.assertEqual(duplicate_log["action"], "manual_review")
        self.assertEqual(duplicate_log["details"]["duplicate_fix_policy"], "safe")

    def test_drop_all_duplicate_policy_removes_conflicting_desc(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "first"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "second"},
            ]
        )

        fixed, logs, _ = process(
            entry,
            [
                "--mode",
                "fix",
                "--fix-verify",
                "all",
                "--duplicate-fix-policy",
                "drop-all",
            ],
        )

        self.assertEqual(fixed["trace"], [entry["trace"][0]])
        duplicate_log = [log for log in logs if log["event_type"] == "duplicate_node"][0]
        self.assertEqual(duplicate_log["action"], "removed")

    def test_duplicate_none_policy_does_not_sync_desc(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "from duplicate"},
            ]
        )

        fixed, logs, _ = process(
            entry,
            [
                "--mode",
                "fix",
                "--fix-verify",
                "all",
                "--duplicate-fix-policy",
                "none",
            ],
        )

        self.assertEqual(fixed["trace"], entry["trace"])
        sync_log = [log for log in logs if log["event_type"] == "duplicate_desc_sync"][0]
        self.assertEqual(sync_log["action"], "manual_review")
        self.assertNotIn("desc", sync_log["after"])

    def test_fix_mode_does_not_change_non_target_verify_bucket(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 50, "code": "dup", "desc": "same"},
                {"file": "same.py", "line": 50, "code": "dup", "desc": "same"},
            ],
            verify=1,
        )

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        duplicate_log = [log for log in logs if log["event_type"] == "duplicate_node"][0]
        self.assertEqual(duplicate_log["action"], "skipped_not_fix_target")

    def test_bounds_policy_removes_post_critical_same_file_node(self):
        entry = make_entry(
            [
                {"file": "same.py", "line": 120, "code": "after", "desc": "after"},
                {"file": "same.py", "line": 80, "code": "keep", "desc": "keep"},
            ]
        )

        fixed, logs, _ = process(
            entry,
            ["--mode", "fix", "--order-fix-policy", "bounds"],
        )

        self.assertEqual(fixed["trace"], [entry["trace"][1]])
        order_log = [log for log in logs if log["event_type"] == "order_after_critical"][0]
        self.assertEqual(order_log["action"], "removed")

    def test_default_order_policy_keeps_post_critical_node_for_review(self):
        entry = make_entry(
            [{"file": "same.py", "line": 120, "code": "after", "desc": "after"}]
        )

        fixed, logs, _ = process(entry, ["--mode", "fix"])

        self.assertEqual(fixed["trace"], entry["trace"])
        order_log = [log for log in logs if log["event_type"] == "order_after_critical"][0]
        self.assertEqual(order_log["action"], "manual_review")


if __name__ == "__main__":
    unittest.main()
