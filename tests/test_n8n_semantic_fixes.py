import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("n8n_fixes", ROOT / "scripts" / "build_n8n_semantic_fixes.py")
fixes = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = fixes
SPEC.loader.exec_module(fixes)


class N8nSemanticFixTests(unittest.TestCase):
    def test_all_issue_entries_are_covered(self):
        self.assertEqual(set(fixes.SPECS), {"entry-00099", "entry-00100", "entry-00103", "entry-00176", "entry-00511", "entry-00512"})

    def test_critical_operations_are_not_rejected_static_anchors(self):
        critical = {entry_id: spec["critical_operation"] for entry_id, spec in fixes.SPECS.items()}
        self.assertNotIn("constants.py", critical["entry-00176"].file)
        self.assertNotEqual(critical["entry-00099"].start, 244)
        self.assertEqual((critical["entry-00511"].file, critical["entry-00511"].start), (fixes.EXTEND, 132))

    def test_generated_patch_matches_declared_sources(self):
        patch = ROOT / "data" / "entries.n8n_semantic_fixed.jsonl"
        rows = [json.loads(line) for line in patch.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assertEqual(row["verify"], 0)
            for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
                self.assertTrue(node["file"] and node["code"] and node["desc"])
                self.assertNotIn("????", node["desc"])

    def test_diff_has_three_rows_per_entry(self):
        import csv
        with (ROOT / "reports" / "n8n_semantic_fix_diff.csv").open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 18)
        self.assertEqual({row["field"] for row in rows}, {"entry_point", "critical_operation", "trace"})


if __name__ == "__main__":
    unittest.main()
