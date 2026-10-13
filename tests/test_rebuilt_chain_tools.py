import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


apply_tools = load_module("apply_rebuild_patches", "scripts/apply_rebuild_patches.py")
verify_tools = load_module("verify_rebuilt_chains", "scripts/verify_rebuilt_chains.py")


class RebuiltChainToolTests(unittest.TestCase):
    def test_parse_line_span_accepts_int_and_range(self):
        self.assertEqual(verify_tools.parse_line_span(7), verify_tools.LineSpan(7, 7))
        self.assertEqual(verify_tools.parse_line_span("7-9"), verify_tools.LineSpan(7, 9))
        self.assertIsNone(verify_tools.parse_line_span(True))
        self.assertIsNone(verify_tools.parse_line_span("9-7"))

    def test_source_slice_matches_multiline_span(self):
        source = "one\ntwo\nthree\nfour\n"
        span = verify_tools.LineSpan(2, 3)

        self.assertEqual(verify_tools.source_slice(source, span), "two\nthree")

    def test_fetch_bytes_retries_transient_network_error(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"ok"
        request = verify_tools.urllib.request.Request("https://example.invalid")

        with (
            mock.patch.object(
                verify_tools.urllib.request,
                "urlopen",
                side_effect=[verify_tools.urllib.error.URLError("transient"), response],
            ) as urlopen,
            mock.patch.object(verify_tools.time, "sleep"),
        ):
            result = verify_tools.fetch_bytes(request, timeout=1)

        self.assertEqual(result, b"ok")
        self.assertEqual(urlopen.call_count, 2)

    def test_apply_patches_replaces_only_target_entry(self):
        base_entries = [
            {"entry_id": "keep", "entry_point": {"file": "a", "line": 1, "code": "a"}, "critical_operation": {"file": "b", "line": 2, "code": "b"}, "trace": []},
            {"entry_id": "patch", "entry_point": {"file": "old", "line": 1, "code": "old"}, "critical_operation": {"file": "b", "line": 2, "code": "b"}, "trace": []},
        ]
        patch_entries = [
            {"entry_id": "patch", "entry_point": {"file": "new", "line": 3, "code": "new"}, "critical_operation": {"file": "b", "line": 2, "code": "b"}, "trace": []},
        ]

        fixed, diff_rows = apply_tools.apply_patches(base_entries, patch_entries)

        self.assertEqual(fixed[0]["entry_id"], "keep")
        self.assertEqual(fixed[1]["entry_point"]["file"], "new")
        self.assertEqual(len(diff_rows), 1)
        self.assertEqual(diff_rows[0]["field_path"], "entry_point")

    def test_verify_current_patch_schema(self):
        entries = verify_tools.read_jsonl(ROOT / "data" / "entries.rebuilt_chains.jsonl")
        errors = verify_tools.validate_entries(entries)

        self.assertEqual(errors, [])

    def test_verify_current_patch_semantic_anchors(self):
        entries = verify_tools.read_jsonl(ROOT / "data" / "entries.rebuilt_chains.jsonl")
        manual_ids = verify_tools.read_manual_review_ids(
            ROOT / "reports" / "rebuild_manual_review.csv"
        )

        errors = verify_tools.validate_target_semantics(entries, manual_ids)

        self.assertEqual(errors, [])

    def test_upstream_fix_evidence_accepts_expected_patches(self):
        entries = verify_tools.read_jsonl(ROOT / "data" / "entries.rebuilt_chains.jsonl")
        by_id = {entry["entry_id"]: entry for entry in entries}
        payloads = {
            "entry-00197": {
                "parents": [{"sha": by_id["entry-00197"]["commit"]}],
                "files": [
                    {
                        "filename": "src/infra/outbound/message-action-params.ts",
                        "patch": (
                            "createRootScopedReadFile normalizeSandboxMediaParams "
                            "hydrateAttachmentParamsForAction"
                        ),
                    }
                ],
            },
            "entry-00290": {
                "parents": [{"sha": by_id["entry-00290"]["commit"]}],
                "files": [
                    {"filename": "src/agents/apply-patch.test.ts", "patch": "test"},
                    {"filename": "src/infra/boundary-path.test.ts", "patch": "test"},
                ],
            },
            "entry-00391": {
                "parents": [{"sha": by_id["entry-00391"]["commit"]}],
                "files": [
                    {
                        "filename": "src/fastmcp/utilities/openapi/director.py",
                        "patch": (
                            "from urllib.parse import quote safe_value "
                            "replace(placeholder, safe_value)"
                        ),
                    }
                ],
            },
        }

        errors = verify_tools.validate_upstream_evidence(entries, payloads)

        self.assertEqual(errors, [])

    def test_upstream_fix_evidence_rejects_parent_and_production_mismatch(self):
        entries = verify_tools.read_jsonl(ROOT / "data" / "entries.rebuilt_chains.jsonl")
        by_id = {entry["entry_id"]: entry for entry in entries}
        payloads = {
            "entry-00197": {
                "parents": [{"sha": "wrong-parent"}],
                "files": [
                    {
                        "filename": "message-action-params.ts",
                        "patch": (
                            "createRootScopedReadFile normalizeSandboxMediaParams "
                            "hydrateAttachmentParamsForAction"
                        ),
                    }
                ],
            },
            "entry-00290": {
                "parents": [{"sha": by_id["entry-00290"]["commit"]}],
                "files": [{"filename": "src/agents/apply-patch.ts", "patch": "production"}],
            },
            "entry-00391": {
                "parents": [{"sha": by_id["entry-00391"]["commit"]}],
                "files": [
                    {
                        "filename": "src/fastmcp/utilities/openapi/director.py",
                        "patch": (
                            "from urllib.parse import quote safe_value "
                            "replace(placeholder, safe_value)"
                        ),
                    }
                ],
            },
        }

        errors = verify_tools.validate_upstream_evidence(entries, payloads)

        self.assertTrue(any("does not match recorded commit" in error for error in errors))
        self.assertTrue(any("test-only changes" in error for error in errors))

    def test_text_integrity_rejects_corrupted_natural_language_only(self):
        entry = {
            "entry_id": "bad",
            "vuln_title": "鍛戒护娉ㄥ叆 ????",
            "entry_point": {"file": "a", "line": 1, "code": "value ???? value", "desc": "clean"},
            "critical_operation": {"file": "b", "line": 2, "code": "b", "desc": "clean"},
            "trace": [],
        }

        errors = verify_tools.validate_text_integrity("bad", entry)

        self.assertTrue(any("replacement question marks" in error for error in errors))
        self.assertTrue(any("mojibake marker" in error for error in errors))
        self.assertFalse(any("entry_point.code" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
