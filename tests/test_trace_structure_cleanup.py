import importlib.util
import sys
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("trace_cleanup", Path(__file__).parents[1] / "scripts" / "trace_structure_cleanup.py")
cleanup = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = cleanup
SPEC.loader.exec_module(cleanup)


def entry(trace, verify=0, ep_file="a.py", co_file="a.py"):
    return {
        "entry_id": "entry-test", "verify": verify,
        "entry_point": {"file": ep_file, "line": 10, "code": "entry"},
        "critical_operation": {"file": co_file, "line": "20-21", "code": "sink"},
        "trace": trace,
    }


class TraceCleanupTests(unittest.TestCase):
    def test_line_span_supports_integer_and_range(self):
        self.assertEqual(cleanup.line_span(4), (4, 4))
        self.assertEqual(cleanup.line_span("4-8"), (4, 8))
        with self.assertRaises(ValueError):
            cleanup.line_span("8-4")

    def test_check_mode_only_reports_duplicate(self):
        node = {"file": "a.py", "line": 12, "code": "x", "desc": "same"}
        result, logs, stats = cleanup.process_entry(entry([node, dict(node)]), "check", "0")
        self.assertEqual(len(result["trace"]), 2)
        self.assertEqual((logs[0]["issue"], logs[0]["action"]), ("duplicate", "review"))
        self.assertEqual(stats["duplicates"], 1)

    def test_fix_removes_identical_duplicate(self):
        node = {"file": "a.py", "line": 12, "code": "x", "desc": "same"}
        result, logs, _ = cleanup.process_entry(entry([node, dict(node)]), "fix", "0")
        self.assertEqual(result["trace"], [node])
        self.assertEqual(logs[0]["action"], "removed")

    def test_conflicting_duplicate_descriptions_require_review(self):
        one = {"file": "a.py", "line": 12, "code": "x", "desc": "first"}
        two = {**one, "desc": "second"}
        result, logs, _ = cleanup.process_entry(entry([one, two]), "fix", "0")
        self.assertEqual(len(result["trace"]), 2)
        self.assertEqual(logs[0]["action"], "review")

    def test_fix_removes_nodes_outside_same_file_bounds(self):
        before = {"file": "a.py", "line": "1-9", "code": "before"}
        after = {"file": "a.py", "line": 22, "code": "after"}
        result, logs, stats = cleanup.process_entry(entry([before, after]), "fix", "0")
        self.assertEqual(result["trace"], [])
        self.assertEqual({row["issue"] for row in logs}, {"before_entry", "after_critical"})
        self.assertEqual(stats["removed_out_of_bounds"], 2)

    def test_overlapping_ranges_are_not_out_of_bounds(self):
        node = {"file": "a.py", "line": "8-10", "code": "overlap"}
        result, logs, _ = cleanup.process_entry(entry([node]), "fix", "0")
        self.assertEqual(result["trace"], [node])
        self.assertEqual(logs, [])

    def test_cross_file_nodes_keep_order(self):
        nodes = [
            {"file": "z.py", "line": 999, "code": "first"},
            {"file": "b.py", "line": 1, "code": "second"},
        ]
        result, logs, stats = cleanup.process_entry(entry(nodes), "fix", "0")
        self.assertEqual(result["trace"], nodes)
        self.assertEqual(logs, [])
        self.assertEqual(stats["cross_file_skipped"], 2)

    def test_verified_entry_is_not_modified_by_default(self):
        node = {"file": "a.py", "line": 1, "code": "before"}
        result, logs, _ = cleanup.process_entry(entry([node], verify=1), "fix", "0")
        self.assertEqual(result["trace"], [node])
        self.assertEqual(logs[0]["action"], "review")


if __name__ == "__main__":
    unittest.main()
