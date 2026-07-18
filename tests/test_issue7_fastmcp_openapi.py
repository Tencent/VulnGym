import csv
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
REBUILT = {"entry-00391", "entry-00394"}
MANUAL_REVIEW = {"entry-00392", "entry-00395"}
SIBLINGS = REBUILT | MANUAL_REVIEW


class FastMcpOpenApiIssue7Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = {}
        with DATA_PATH.open(encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                if record["entry_id"] in SIBLINGS:
                    cls.entries[record["entry_id"]] = record

    def test_all_four_advisory_siblings_are_accounted_for(self):
        self.assertEqual(set(self.entries), SIBLINGS)
        self.assertEqual(
            {record["report_id"] for record in self.entries.values()},
            {"GHSA-VV7Q-7JX5-F767"},
        )

    def test_rebuilt_entries_are_directly_fix_backed(self):
        for entry_id in REBUILT:
            record = self.entries[entry_id]
            self.assertEqual(record["verify"], 1)
            self.assertEqual(
                record["critical_operation"]["file"],
                "src/fastmcp/utilities/openapi/director.py",
            )
            self.assertEqual(record["critical_operation"]["line"], "208-213")
            self.assertIn(
                "url_path = url_path.replace",
                record["critical_operation"]["code"],
            )

    def test_entry_00391_removes_logger_and_declaration_anchors(self):
        record = self.entries["entry-00391"]
        trace_text = "\n".join(node["code"] for node in record["trace"])
        self.assertNotIn("logger.", trace_text)
        self.assertNotEqual(
            record["critical_operation"]["code"],
            "    def _build_url(",
        )
        self.assertIn("urljoin", trace_text)

    def test_entry_00394_covers_external_input_root_cause_and_effect(self):
        record = self.entries["entry-00394"]
        self.assertEqual(
            record["entry_point"]["code"],
            "    async def run(self, arguments: dict[str, Any]) -> ToolResult:",
        )
        trace_text = "\n".join(node["code"] for node in record["trace"])
        self.assertIn("self._director.build", trace_text)
        self.assertIn("url_path = url_path.replace", trace_text)
        self.assertIn("self._client.send(request)", trace_text)

    def test_uncertain_resource_entries_are_in_manual_review(self):
        path = ROOT / "reports" / "issue-7-fastmcp-openapi.manual_review.csv"
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual({row["entry_id"] for row in rows}, MANUAL_REVIEW)
        for row in rows:
            self.assertIn("Fix 40bdfb6", row["fix_evidence"])
            self.assertTrue(row["candidate_action"])

    def test_diff_artifact_contains_only_canonical_rebuilds(self):
        path = ROOT / "reports" / "issue-7-fastmcp-openapi.diff.csv"
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        changed = {row["entry_id"] for row in rows}
        self.assertEqual(changed, REBUILT)
        self.assertTrue(
            {"entry_point", "critical_operation", "trace"}
            <= {row["field"] for row in rows}
        )

    def test_readme_audit_statistics_match_dataset(self):
        entries = []
        with DATA_PATH.open(encoding="utf-8") as handle:
            entries = [json.loads(line) for line in handle]
        verified = [entry for entry in entries if entry["verify"] == 1]
        verified_reports = {entry["report_id"] for entry in verified}
        self.assertEqual(len(verified), 394)
        self.assertEqual(len(verified_reports), 178)
        for filename in ("README.md", "README_zh.md"):
            text = (ROOT / filename).read_text(encoding="utf-8")
            self.assertIn("394 / 408 (96.6", text)
            self.assertIn("178 / 184 (96.7", text)


if __name__ == "__main__":
    unittest.main()
