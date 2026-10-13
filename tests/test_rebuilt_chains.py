import csv
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("rebuild", ROOT / "scripts" / "build_rebuilt_chains.py")
rebuild = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = rebuild
SPEC.loader.exec_module(rebuild)


class RebuiltChainTests(unittest.TestCase):
    def test_target_set_is_complete(self):
        self.assertEqual(set(rebuild.SPECS), {"entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391"})

    def test_known_weak_anchors_are_not_critical_operations(self):
        for spec in rebuild.SPECS.values():
            critical = spec["critical_operation"]
            self.assertNotEqual(critical.file, "src/infra/boundary-path.ts")
            self.assertGreater(critical.end, 0)

    def test_generated_patch_shape(self):
        rows = [json.loads(x) for x in (ROOT / "data" / "entries.rebuilt_chains.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 5)
        for row in rows:
            self.assertEqual(row["verify"], 0)
            for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
                self.assertTrue(node["file"] and node["code"] and node["desc"])

    def test_diff_and_manual_review_outputs(self):
        with (ROOT / "reports" / "rebuild_fix_diff.csv").open(encoding="utf-8-sig", newline="") as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 15)
        with (ROOT / "reports" / "rebuild_manual_review.csv").open(encoding="utf-8-sig", newline="") as handle:
            self.assertEqual(list(csv.DictReader(handle)), [])


if __name__ == "__main__":
    unittest.main()
