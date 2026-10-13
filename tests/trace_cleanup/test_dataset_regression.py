from __future__ import annotations

import unittest
from pathlib import Path

from tools.trace_cleanup.detect import scan_entries
from tools.trace_cleanup.io import load_jsonl
from tools.trace_cleanup.policy import decide_findings


REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRIES = REPO_ROOT / "data" / "entries.jsonl"


class DatasetRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = load_jsonl(ENTRIES)
        cls.result = scan_entries(cls.entries)

    def test_current_duplicate_groups_are_protected_desc_conflicts(self) -> None:
        duplicates = [
            finding
            for finding in self.result.findings
            if finding.rule_id == "duplicate_trace_node"
        ]
        self.assertEqual(len(duplicates), 7)
        self.assertEqual(
            [finding.entry_id for finding in duplicates],
            [
                "entry-00115",
                "entry-00182",
                "entry-00199",
                "entry-00224",
                "entry-00484",
                "entry-00487",
                "entry-00507",
            ],
        )
        self.assertTrue(all(finding.verify == 1 for finding in duplicates))
        self.assertTrue(all(not finding.safe_duplicate for finding in duplicates))
        decisions = decide_findings(
            duplicates,
            mode="fix",
            duplicate_action="remove-safe",
            order_action="report",
        )
        self.assertTrue(all(d.status == "protected_verified" for d in decisions))
        self.assertTrue(all(not d.remove_indices for d in decisions))

    def test_priority_samples_have_expected_classification(self) -> None:
        actual = {
            (finding.entry_id, finding.rule_id, finding.trace_index)
            for finding in self.result.findings
        }
        expected = {
            ("entry-00103", "before_entry_definite", 1),
            ("entry-00103", "overlap_critical", 3),
            ("entry-00185", "after_critical_definite", 2),
            ("entry-00320", "before_entry_definite", 2),
            ("entry-00511", "overlap_entry", 0),
            ("entry-00511", "after_critical_definite", 4),
            ("entry-00511", "overlap_critical", 5),
        }
        self.assertTrue(expected.issubset(actual))
