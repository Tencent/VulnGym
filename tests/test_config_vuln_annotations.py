from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import apply_config_vuln_patches as gen  # noqa: E402
import verify_config_vuln_annotations as verify  # noqa: E402


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
            gen.source_slice("scripts/e2e/Dockerfile.qr-import", 9),
            "RUN pnpm install --frozen-lockfile",
        )

    def test_patch_rows_are_schema_compatible(self) -> None:
        baseline_rows = gen.load_jsonl(gen.BASELINE_JSONL)
        patch_rows = gen.build_patch_rows(baseline_rows)
        gen.validate_patch_rows(patch_rows)
        self.assertEqual([row["entry_id"] for row in patch_rows], list(gen.TARGET_IDS))
        for row in patch_rows:
            self.assertEqual(row["commit"], gen.UPSTREAM_COMMIT)
            self.assertEqual(row["verify"], 1)
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
            "17-18",
        )
        self.assertEqual(
            fixed_by_id["entry-00244"]["critical_operation"]["line"],
            18,
        )

    def test_semantic_anchors_use_narrow_effect_points(self) -> None:
        patch_rows = gen.build_patch_rows(gen.load_jsonl(gen.BASELINE_JSONL))

        verify.check_semantic_anchors(patch_rows)

        by_id = {row["entry_id"]: row for row in patch_rows}
        self.assertEqual(by_id["entry-00241"]["critical_operation"]["line"], 23)
        self.assertEqual(by_id["entry-00242"]["critical_operation"]["line"], 9)
        self.assertEqual(by_id["entry-00243"]["critical_operation"]["line"], 14)
        self.assertEqual(by_id["entry-00244"]["critical_operation"]["line"], 18)

    def test_upstream_evidence_accepts_fix_and_advisory_distinction(self) -> None:
        fix_payload = {
            "sha": gen.FIX_COMMIT,
            "files": [
                {"filename": path, "patch": "+RUN useradd appuser\n+USER appuser"}
                for path in verify.MISSING_USER_FILES
            ],
        }
        compare_payload = {
            "status": "ahead",
            "behind_by": 0,
            "merge_base_commit": {"sha": gen.UPSTREAM_COMMIT},
        }
        advisory_payload = {
            "ghsa_id": verify.ADVISORY_ID,
            "description": "\n".join(
                [*verify.MISSING_USER_FILES, verify.NONROOT_FILE, "NOPASSWD sudo"]
            ),
        }

        verify.validate_upstream_evidence(
            fix_payload,
            compare_payload,
            advisory_payload,
        )

    def test_upstream_evidence_rejects_wrong_ancestry_and_scope(self) -> None:
        fix_payload = {
            "sha": gen.FIX_COMMIT,
            "files": [
                {"filename": path, "patch": "+USER appuser"}
                for path in (*verify.MISSING_USER_FILES, verify.NONROOT_FILE)
            ],
        }
        compare_payload = {
            "status": "diverged",
            "behind_by": 1,
            "merge_base_commit": {"sha": "wrong"},
        }
        advisory_payload = {
            "ghsa_id": verify.ADVISORY_ID,
            "description": "\n".join(
                [*verify.MISSING_USER_FILES, verify.NONROOT_FILE, "NOPASSWD sudo"]
            ),
        }

        with self.assertRaisesRegex(AssertionError, "not an ancestor"):
            verify.validate_upstream_evidence(
                fix_payload,
                compare_payload,
                advisory_payload,
            )

    def test_text_integrity_rejects_replacement_damage(self) -> None:
        patch_rows = gen.build_patch_rows(gen.load_jsonl(gen.BASELINE_JSONL))
        patch_rows[0]["vuln_title"] = "damaged ???? title"

        with self.assertRaisesRegex(AssertionError, "encoding damage"):
            verify.check_text_integrity(patch_rows)

    def test_fetch_bytes_retries_transient_network_error(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"ok"
        request = verify.urllib.request.Request("https://example.invalid")

        with (
            mock.patch.object(
                verify.urllib.request,
                "urlopen",
                side_effect=[verify.urllib.error.URLError("transient"), response],
            ) as urlopen,
            mock.patch.object(verify.time, "sleep"),
        ):
            result = verify.fetch_bytes(request, timeout=1)

        self.assertEqual(result, b"ok")
        self.assertEqual(urlopen.call_count, 2)


if __name__ == "__main__":
    unittest.main()
