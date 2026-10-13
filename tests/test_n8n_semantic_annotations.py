from __future__ import annotations

import copy
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import apply_n8n_semantic_patches as gen  # noqa: E402
import verify_n8n_semantic_annotations as verify  # noqa: E402


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return b"ok"


class N8nSemanticAnnotationTests(unittest.TestCase):
    def test_target_patch_rows_are_valid_and_reviewed(self) -> None:
        patch_rows = gen.load_jsonl(gen.PATCH_JSONL)
        gen.validate_patch_rows(patch_rows)
        self.assertEqual([row["entry_id"] for row in patch_rows], list(gen.TARGET_IDS))
        self.assertTrue(all(row["verify"] == 1 for row in patch_rows))

    def test_full_fixed_preserves_baseline_order_and_count(self) -> None:
        baseline_rows = gen.load_jsonl(gen.BASELINE_JSONL)
        patch_rows = gen.load_jsonl(gen.PATCH_JSONL)
        fixed_rows = gen.apply_patch_rows(baseline_rows, patch_rows)
        self.assertEqual(len(fixed_rows), len(baseline_rows))
        self.assertEqual(
            [row["entry_id"] for row in fixed_rows],
            [row["entry_id"] for row in baseline_rows],
        )

    def test_only_target_rows_change(self) -> None:
        baseline_rows = gen.load_jsonl(gen.BASELINE_JSONL)
        patch_rows = gen.load_jsonl(gen.PATCH_JSONL)
        fixed_rows = gen.apply_patch_rows(baseline_rows, patch_rows)
        changed = {
            old["entry_id"]
            for old, new in zip(baseline_rows, fixed_rows, strict=True)
            if old != new
        }
        self.assertEqual(changed, set(gen.TARGET_IDS))

    def test_semantic_anchors_match_reviewed_chains(self) -> None:
        verify.check_semantic_anchors(gen.load_jsonl(gen.PATCH_JSONL))

    def test_manual_run_entry_uses_request_handoff_not_route_metadata(self) -> None:
        rows = {row["entry_id"]: row for row in gen.load_jsonl(gen.PATCH_JSONL)}
        entry = rows["entry-00099"]["entry_point"]
        self.assertEqual(entry["line"], "561-565")
        self.assertIn("executeManually", entry["code"])
        self.assertIn("req.body", entry["code"])
        self.assertNotIn("@Post", entry["code"])

    def test_policy_gap_is_critical_and_exec_is_impact_for_python(self) -> None:
        rows = {row["entry_id"]: row for row in gen.load_jsonl(gen.PATCH_JSONL)}
        python_row = rows["entry-00176"]
        self.assertEqual(
            python_row["critical_operation"]["file"],
            "packages/@n8n/task-runner-python/src/task_analyzer.py",
        )
        self.assertIn("BLOCKED_ATTRIBUTES", python_row["critical_operation"]["code"])
        self.assertIn("exec(compiled_code, globals)", python_row["trace"][-1]["code"])

    def test_no_question_mark_encoding_damage_in_patch_text(self) -> None:
        for row in gen.load_jsonl(gen.PATCH_JSONL):
            for value in gen.iter_text_values(row):
                self.assertIsNone(gen.DAMAGED_TEXT_RE.search(value))

    def test_fix_evidence_accepts_exact_parent_and_markers(self) -> None:
        payloads = {
            report_id: {
                "sha": evidence["sha"],
                "parents": [{"sha": evidence["parent"]}],
                "files": [{"patch": "\n".join(evidence["markers"])}],
            }
            for report_id, evidence in verify.FIX_EVIDENCE.items()
        }
        verify.check_fix_evidence(payloads)

    def test_fix_evidence_rejects_unrelated_parent(self) -> None:
        payloads = {
            report_id: {
                "sha": evidence["sha"],
                "parents": [{"sha": evidence["parent"]}],
                "files": [{"patch": "\n".join(evidence["markers"])}],
            }
            for report_id, evidence in verify.FIX_EVIDENCE.items()
        }
        broken = copy.deepcopy(payloads)
        broken["GHSA-825Q-W924-XHGX"]["parents"][0]["sha"] = "0" * 40
        with self.assertRaisesRegex(AssertionError, "not the fix's first parent"):
            verify.check_fix_evidence(broken)

    @mock.patch.object(verify.time, "sleep")
    @mock.patch.object(verify.urllib.request, "urlopen")
    def test_fetch_bytes_retries_transient_url_error(
        self, urlopen: mock.Mock, sleep: mock.Mock
    ) -> None:
        urlopen.side_effect = [urllib.error.URLError("temporary"), FakeResponse()]
        self.assertEqual(verify.fetch_bytes("https://example.invalid", attempts=2), b"ok")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
