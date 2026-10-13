import csv
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("config_fixes", ROOT / "scripts" / "build_config_vuln_annotations.py")
fixes = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = fixes
SPEC.loader.exec_module(fixes)


class ConfigVulnerabilityAnnotationTests(unittest.TestCase):
    def test_all_four_entries_are_covered(self):
        self.assertEqual(set(fixes.SPECS), {"entry-00241", "entry-00242", "entry-00243", "entry-00244"})

    def test_root_inheritance_entries_start_at_from(self):
        for entry_id in ("entry-00241", "entry-00242", "entry-00243"):
            self.assertEqual(fixes.SPECS[entry_id]["entry_point"].start, 1)

    def test_nonroot_variant_targets_sudoers_rule(self):
        critical = fixes.SPECS["entry-00244"]["critical_operation"]
        self.assertEqual((critical.start, critical.end), (17, 18))

    def test_generated_artifacts(self):
        rows = [json.loads(x) for x in (ROOT / "data" / "entries.config_vuln_fixed.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 4)
        for row in rows:
            for node in [row["entry_point"], row["critical_operation"], *row["trace"]]:
                self.assertTrue(node["file"] and node["code"] and node["desc"])
                self.assertTrue(any(term in node["desc"].lower() for term in ("root", "privilege", "user", "sudo")))
        with (ROOT / "reports" / "config_vuln_fix_diff.csv").open(encoding="utf-8-sig", newline="") as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 12)


if __name__ == "__main__":
    unittest.main()
