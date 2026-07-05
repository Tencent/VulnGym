import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
