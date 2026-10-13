from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import trace_cleanup as cleanup  # noqa: E402
import verify_trace_cleanup_artifacts as verifier  # noqa: E402


class TraceCleanupArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source, cls.fixed, cls.logs, cls.report = verifier.regenerate()

    def test_fixed_jsonl_is_reproducible(self) -> None:
        committed = cleanup.load_jsonl(verifier.FIXED_PATH)
        self.assertEqual(committed, self.fixed)
        verifier.compare_generated_files(self.fixed, self.logs, self.report)

    def test_only_trace_nodes_are_removed_without_reordering(self) -> None:
        changed_ids = verifier.check_row_invariants(self.source, self.fixed)
        self.assertEqual(changed_ids, verifier.EXPECTED_CHANGED_IDS)

    def test_report_hashes_cover_input_and_output_rows(self) -> None:
        artifacts = self.report["artifacts"]
        self.assertEqual(artifacts["format_version"], cleanup.ARTIFACT_FORMAT_VERSION)
        self.assertEqual(
            artifacts["input_rows_sha256"],
            cleanup.rows_sha256(self.source),
        )
        self.assertEqual(
            artifacts["output_rows_sha256"],
            cleanup.rows_sha256(self.fixed),
        )

    def test_compact_audit_artifacts_match_applied_events(self) -> None:
        changed_ids = verifier.check_row_invariants(self.source, self.fixed)
        diff_rows, review_rows = verifier.check_audit_artifacts(
            changed_ids, self.logs, self.report
        )
        self.assertEqual(diff_rows, 2)
        self.assertGreater(review_rows, 0)
        for row in verifier.load_csv(verifier.DIFF_CSV):
            self.assertNotIn("desc", json.loads(row["before_json"]))
            self.assertEqual(len(row["before_desc_sha256"]), 64)

    def test_priority_samples_have_conservative_outcomes(self) -> None:
        outcomes = {
            (log["entry_id"], log["event_type"], log["action"])
            for log in self.logs
        }
        self.assertIn(("entry-00103", "order_before_entry", "removed"), outcomes)
        self.assertIn(("entry-00320", "order_before_entry", "removed"), outcomes)
        self.assertIn(("entry-00185", "order_after_critical", "manual_review"), outcomes)
        self.assertIn(("entry-00511", "order_after_critical", "manual_review"), outcomes)


if __name__ == "__main__":
    unittest.main()
