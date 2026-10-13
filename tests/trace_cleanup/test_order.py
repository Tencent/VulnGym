from __future__ import annotations

import unittest

from tools.trace_cleanup.detect import detect_entry, normalize_path
from tools.trace_cleanup.policy import apply_decisions, decide_findings

from .fixtures import entry, node


class OrderDetectionTests(unittest.TestCase):
    def test_definite_before_and_after(self) -> None:
        value = entry(trace=[node(5), node(25)])
        rules = {(f.rule_id, f.trace_index) for f in detect_entry(value)}
        self.assertIn(("before_entry_definite", 0), rules)
        self.assertIn(("after_critical_definite", 1), rules)

    def test_equal_and_contained_are_not_order_findings(self) -> None:
        value = entry(
            entry_point=node("10-20", code="entry"),
            critical_operation=node("30-40", code="critical"),
            trace=[node("10-20"), node("12-18"), node("32-38")],
        )
        rules = {f.rule_id for f in detect_entry(value)}
        self.assertNotIn("before_entry_definite", rules)
        self.assertNotIn("after_critical_definite", rules)

    def test_left_and_right_overlap_are_reported_not_definite(self) -> None:
        value = entry(
            entry_point=node("10-20", code="entry"),
            critical_operation=node("30-40", code="critical"),
            trace=[node("5-15"), node("35-45")],
        )
        rules = {(f.rule_id, f.trace_index) for f in detect_entry(value)}
        self.assertIn(("overlap_entry", 0), rules)
        self.assertIn(("overlap_critical", 1), rules)
        self.assertNotIn(("before_entry_definite", 0), rules)
        self.assertNotIn(("after_critical_definite", 1), rules)

    def test_contains_boundaries_is_overlap_not_definite(self) -> None:
        value = entry(
            entry_point=node(10, code="entry"),
            critical_operation=node("30-35", code="critical"),
            trace=[node("5-15"), node("25-40")],
        )
        rules = {(f.rule_id, f.trace_index) for f in detect_entry(value)}
        self.assertIn(("overlap_entry", 0), rules)
        self.assertIn(("overlap_critical", 1), rules)

    def test_cross_file_is_skipped(self) -> None:
        value = entry(trace=[node(1, file="other.py")])
        finding = next(f for f in detect_entry(value) if f.rule_id == "cross_file_skipped")
        self.assertEqual(finding.trace_index, 0)

    def test_path_normalization_is_limited_and_case_sensitive(self) -> None:
        self.assertEqual(normalize_path(r".\src\example.py"), "src/example.py")
        self.assertNotEqual(normalize_path("Src/example.py"), normalize_path("src/example.py"))
        value = entry(trace=[node(5, file=r".\src\example.py")])
        rules = {(f.rule_id, f.trace_index) for f in detect_entry(value)}
        self.assertIn(("before_entry_definite", 0), rules)

    def test_default_fix_does_not_delete_order_candidate(self) -> None:
        value = entry(trace=[node(5), node(20)])
        decisions = decide_findings(
            detect_entry(value),
            mode="fix",
            duplicate_action="remove-safe",
            order_action="report",
        )
        result = apply_decisions([value], decisions)
        self.assertEqual([n["line"] for n in result.entries[0]["trace"]], [5, 20])

    def test_explicit_remove_definite_deletes_unverified_candidate(self) -> None:
        value = entry(trace=[node(5), node(10), node(25)])
        decisions = decide_findings(
            detect_entry(value),
            mode="fix",
            duplicate_action="report",
            order_action="remove-definite",
        )
        result = apply_decisions([value], decisions)
        self.assertEqual([n["line"] for n in result.entries[0]["trace"]], [10])

    def test_caller_callee_descent_is_never_deleted_by_default(self) -> None:
        value = entry(
            critical_operation=node(20, code="callee"),
            trace=[node(50, code="caller invokes callee")],
        )
        decisions = decide_findings(
            detect_entry(value),
            mode="fix",
            duplicate_action="remove-safe",
            order_action="report",
        )
        result = apply_decisions([value], decisions)
        self.assertEqual(len(result.entries[0]["trace"]), 1)
