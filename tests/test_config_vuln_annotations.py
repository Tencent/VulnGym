from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import apply_config_vuln_patches as gen  # noqa: E402


class ConfigVulnAnnotationTests(unittest.TestCase):
    def test_source_slices_match_line_ranges(self) -> None:
        self.assertEqual(
            gen.source_slice("scripts/e2e/Dockerfile", 23),
            'CMD ["bash"]',
        )
        self.assertIn(
            "NOPASSWD:ALL",
            gen.source_slice("scripts/docker/install-sh-nonroot/Dockerfile", "17-20"),
        )
        self.assertEqual(
            len(gen.source_slice("scripts/e2e/Dockerfile.qr-import", "1-9").splitlines()),
            9,
        )

    def test_patch_rows_are_schema_compatible(self) -> None:
        baseline_rows = gen.load_jsonl(gen.BASELINE_JSONL)
        patch_rows = gen.build_patch_rows(baseline_rows)
        gen.validate_patch_rows(patch_rows)
        self.assertEqual([row["entry_id"] for row in patch_rows], list(gen.TARGET_IDS))
        for row in patch_rows:
            self.assertEqual(row["commit"], gen.UPSTREAM_COMMIT)
            self.assertEqual(row["verify"], 0)
            for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
                self.assertNotIn("??", node["desc"])
                self.assertEqual(node["code"], gen.source_slice(node["file"], node["line"]))

    def test_full_fixed_preserves_row_count_and_order(self) -> None:
        baseline_rows = gen.load_jsonl(gen.BASELINE_JSONL)
        patch_rows = gen.build_patch_rows(baseline_rows)
        fixed_rows = gen.apply_patch_rows(baseline_rows, patch_rows)
        self.assertEqual(len(fixed_rows), len(baseline_rows))
        self.assertEqual(
            [row["entry_id"] for row in fixed_rows],
            [row["entry_id"] for row in baseline_rows],
        )
        fixed_by_id = {row["entry_id"]: row for row in fixed_rows}
        self.assertEqual(
            fixed_by_id["entry-00244"]["entry_point"]["line"],
            17,
        )
        self.assertEqual(
            fixed_by_id["entry-00244"]["critical_operation"]["line"],
            "17-20",
        )


if __name__ == "__main__":
    unittest.main()
