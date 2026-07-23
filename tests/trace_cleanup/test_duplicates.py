from __future__ import annotations

import unittest

from tools.trace_cleanup.detect import detect_entry
from tools.trace_cleanup.policy import apply_decisions, decide_findings

from .fixtures import entry, node


def duplicate_findings(value: dict) -> list:
    return [f for f in detect_entry(value) if f.rule_id == "duplicate_trace_node"]


class DuplicateDetectionTests(unittest.TestCase):
    def test_adjacent_duplicate_with_same_desc_is_safe(self) -> None:
        repeated = node(12, code="repeat", desc="same")
        value = entry(trace=[repeated, repeated, node(20)])
        finding = duplicate_findings(value)[0]
        self.assertEqual(finding.indices, (0, 1))
        self.assertTrue(finding.safe_duplicate)

    def test_non_adjacent_and_three_duplicates(self) -> None:
        repeated = node(12, code="repeat", desc="same")
        value = entry(trace=[repeated, node(15), repeated, repeated])
        finding = duplicate_findings(value)[0]
        self.assertEqual(finding.indices, (0, 2, 3))

    def test_all_missing_desc_is_safe(self) -> None:
        repeated = node(12, code="repeat", include_desc=False)
        finding = duplicate_findings(entry(trace=[repeated, repeated]))[0]
        self.assertTrue(finding.safe_duplicate)

    def test_different_desc_requires_review(self) -> None:
        first = node(12, code="repeat", desc="first role")
        second = node(12, code="repeat", desc="second role")
        finding = duplicate_findings(entry(trace=[first, second]))[0]
        self.assertFalse(finding.safe_duplicate)

    def test_present_and_missing_desc_requires_review(self) -> None:
        first = node(12, code="repeat", desc="role")
        second = node(12, code="repeat", include_desc=False)
        finding = duplicate_findings(entry(trace=[first, second]))[0]
        self.assertFalse(finding.safe_duplicate)

    def test_integer_and_single_line_range_are_not_duplicates(self) -> None:
        value = entry(
            trace=[
                node(97, code="same", desc="same"),
                node("97-97", code="same", desc="same"),
            ]
        )
        self.assertEqual(duplicate_findings(value), [])

    def test_endpoint_overlap_is_not_internal_duplicate(self) -> None:
        endpoint = node(10, code="entry")
        critical = node(20, code="critical")
        value = entry(
            entry_point=endpoint,
            critical_operation=critical,
            trace=[endpoint, critical],
        )
        self.assertEqual(duplicate_findings(value), [])

    def test_fix_keeps_first_and_preserves_remaining_order(self) -> None:
        repeated = node(12, code="repeat", desc="same")
        value = entry(trace=[node(10), repeated, node(15), repeated, node(20)])
        findings = detect_entry(value)
        decisions = decide_findings(
            findings,
            mode="fix",
            duplicate_action="remove-safe",
            order_action="report",
        )
        result = apply_decisions([value], decisions)
        self.assertEqual(
            [item["line"] for item in result.entries[0]["trace"]],
            [10, 12, 15, 20],
        )
        self.assertEqual(result.changed_entries, 1)

    def test_verified_duplicate_is_not_modified(self) -> None:
        repeated = node(12, code="repeat", desc="same")
        value = entry(verify=1, trace=[repeated, repeated])
        decisions = decide_findings(
            detect_entry(value),
            mode="fix",
            duplicate_action="remove-safe",
            order_action="report",
        )
        result = apply_decisions([value], decisions)
        self.assertEqual(len(result.entries[0]["trace"]), 2)
        duplicate = next(d for d in decisions if d.finding.rule_id == "duplicate_trace_node")
        self.assertEqual(duplicate.status, "protected_verified")
