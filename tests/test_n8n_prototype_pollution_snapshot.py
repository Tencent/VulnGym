import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_n8n_prototype_pollution_snapshot.py"
SPEC = importlib.util.spec_from_file_location("n8n_snapshot_fix", SCRIPT)
fix = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = fix
SPEC.loader.exec_module(fix)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class N8nPrototypePollutionSnapshotTests(unittest.TestCase):
    def test_all_report_entries_share_the_vulnerable_snapshot(self) -> None:
        all_entries = read_jsonl(ROOT / "data" / "entries.jsonl")
        reports = read_jsonl(ROOT / "data" / "reports.jsonl")
        entries = fix.validate_dataset(all_entries, reports)
        report = next(row for row in reports if row["report_id"] == fix.REPORT_ID)

        self.assertEqual(set(entries), set(fix.TARGET_IDS))
        self.assertEqual(report["commit"], fix.VULNERABLE_COMMIT)
        self.assertEqual({row["commit"] for row in entries.values()}, {fix.VULNERABLE_COMMIT})
        self.assertEqual({row["verify"] for row in entries.values()}, {0})

    def test_semantic_roles_point_to_inputs_and_real_writes(self) -> None:
        entries = {
            row["entry_id"]: row
            for row in read_jsonl(ROOT / "data" / "entries.jsonl")
            if row["entry_id"] in fix.TARGET_IDS
        }

        self.assertIn("additionalFields.customFields", entries["entry-00359"]["entry_point"]["code"])
        self.assertIn("[fieldName] = value", entries["entry-00359"]["critical_operation"]["code"])
        self.assertIn("updateFields.customFields", entries["entry-00360"]["entry_point"]["code"])
        self.assertIn("[fieldName] = value", entries["entry-00360"]["critical_operation"]["code"])
        self.assertIn("getNodeParameter('options'", entries["entry-00361"]["entry_point"]["code"])
        self.assertIn("parseStringPromise", entries["entry-00361"]["critical_operation"]["code"])

        serialized = json.dumps(entries, ensure_ascii=False)
        self.assertNotIn("let item: INodeExecutionData", serialized)
        self.assertNotIn("getNodeParameter('dataPropertyName', 0)", entries["entry-00361"]["entry_point"]["code"])

    def test_validator_rejects_mixed_snapshots_and_review_state(self) -> None:
        entries = read_jsonl(ROOT / "data" / "entries.jsonl")
        reports = read_jsonl(ROOT / "data" / "reports.jsonl")
        stale = copy.deepcopy(entries)
        target = next(row for row in stale if row["entry_id"] == "entry-00361")
        target["commit"] = "0" * 40
        with self.assertRaisesRegex(fix.VerificationError, "mixed or stale snapshot"):
            fix.validate_dataset(stale, reports)

        reviewed = copy.deepcopy(entries)
        next(row for row in reviewed if row["entry_id"] == "entry-00361")["verify"] = 1
        with self.assertRaisesRegex(fix.VerificationError, "await maintainer review"):
            fix.validate_dataset(reviewed, reports)

    def test_cli_accepts_canonical_files(self) -> None:
        self.assertEqual(fix.main([]), 0)

    def test_source_slice_supports_single_lines_and_ranges(self) -> None:
        source = "one\ntwo\nthree\nfour\n"
        self.assertEqual(fix.source_slice(source, 2), "two")
        self.assertEqual(fix.source_slice(source, "2-3"), "two\nthree")

    def test_current_readme_counts_match_downgraded_review_state(self) -> None:
        entries = read_jsonl(ROOT / "data" / "entries.jsonl")
        verified = [row for row in entries if row["verify"] == 1]
        verified_reports = {row["report_id"] for row in verified}
        self.assertEqual((len(verified), len(verified_reports)), (390, 177))

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        readme_zh = (ROOT / "README_zh.md").read_text(encoding="utf-8")
        self.assertIn("390 / 408 (95.6 %)", readme)
        self.assertIn("177 / 184 (96.2 %)", readme)
        self.assertIn("390 / 408 (95.6%)", readme_zh)
        self.assertIn("177 / 184 (96.2%)", readme_zh)


if __name__ == "__main__":
    unittest.main()
