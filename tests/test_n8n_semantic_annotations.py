from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import apply_n8n_semantic_patches as gen  # noqa: E402


class N8nSemanticAnnotationTests(unittest.TestCase):
    def test_target_patch_rows_are_valid(self) -> None:
        patch_rows = gen.load_jsonl(gen.PATCH_JSONL)
        gen.validate_patch_rows(patch_rows)
        self.assertEqual([row["entry_id"] for row in patch_rows], list(gen.TARGET_IDS))

    def test_patch_preserves_canonical_order_and_count(self) -> None:
        canonical_rows = gen.load_jsonl(gen.CANONICAL_JSONL)
        patch_rows = gen.load_jsonl(gen.PATCH_JSONL)
        fixed_rows = gen.apply_patch_rows(canonical_rows, patch_rows)
        self.assertEqual(len(fixed_rows), len(canonical_rows))
        self.assertEqual(
            [row["entry_id"] for row in fixed_rows],
            [row["entry_id"] for row in canonical_rows],
        )
        self.assertTrue(gen.canonical_has_patch(fixed_rows, patch_rows))

    def test_semantic_locations_are_not_old_bad_sinks(self) -> None:
        patch_rows = {row["entry_id"]: row for row in gen.load_jsonl(gen.PATCH_JSONL)}
        self.assertEqual(
            patch_rows["entry-00099"]["critical_operation"]["file"],
            "packages/workflow/src/expression-evaluator-proxy.ts",
        )
        self.assertEqual(
            patch_rows["entry-00100"]["critical_operation"]["file"],
            "packages/workflow/src/expression-evaluator-proxy.ts",
        )
        self.assertEqual(
            patch_rows["entry-00176"]["critical_operation"]["code"].strip(),
            "exec(compiled_code, globals)",
        )
        self.assertEqual(
            patch_rows["entry-00103"]["entry_point"]["file"],
            "packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts",
        )

    def test_no_question_mark_encoding_damage_in_target_descs(self) -> None:
        for row in gen.load_jsonl(gen.PATCH_JSONL):
            for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
                self.assertIsNone(gen.DAMAGED_TEXT_RE.search(node.get("desc", "")))


if __name__ == "__main__":
    unittest.main()
