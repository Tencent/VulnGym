from __future__ import annotations

import unittest

from tools.trace_cleanup.detect import detect_entry
from tools.trace_cleanup.policy import decide_findings

from .fixtures import entry, node


class PolicyTests(unittest.TestCase):
    def test_ambiguous_duplicate_needs_human(self) -> None:
        value = entry(
            trace=[
                node(12, code="repeat", desc="first"),
                node(12, code="repeat", desc="second"),
            ]
        )
        decision = next(
            d
            for d in decide_findings(
                detect_entry(value),
                mode="fix",
                duplicate_action="remove-safe",
                order_action="report",
            )
            if d.finding.rule_id == "duplicate_trace_node"
        )
        self.assertEqual(decision.status, "manual_review")
        self.assertEqual(decision.remove_indices, ())

    def test_check_only_reports_safe_duplicate(self) -> None:
        repeated = node(12, code="repeat", desc="same")
        value = entry(trace=[repeated, repeated])
        decision = next(
            d
            for d in decide_findings(
                detect_entry(value),
                mode="check",
                duplicate_action="report",
                order_action="report",
            )
            if d.finding.rule_id == "duplicate_trace_node"
        )
        self.assertEqual(decision.status, "reported")

    def test_cross_file_has_skipped_status(self) -> None:
        value = entry(trace=[node(1, file="other.py")])
        decision = next(
            d
            for d in decide_findings(
                detect_entry(value),
                mode="check",
                duplicate_action="report",
                order_action="report",
            )
            if d.finding.rule_id == "cross_file_skipped"
        )
        self.assertEqual(decision.status, "skipped_cross_file")

    def test_verified_order_finding_is_protected(self) -> None:
        value = entry(verify=1, trace=[node(5)])
        decision = next(
            d
            for d in decide_findings(
                detect_entry(value),
                mode="fix",
                duplicate_action="report",
                order_action="remove-definite",
            )
            if d.finding.rule_id == "before_entry_definite"
        )
        self.assertEqual(decision.status, "protected_verified")
        self.assertEqual(decision.remove_indices, ())
