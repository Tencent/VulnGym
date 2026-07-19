import csv
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
TARGETS = {
    "entry-00241",
    "entry-00242",
    "entry-00243",
    "entry-00244",
}
SCRIPT_PATH = ROOT / "scripts" / "apply_issue8_config_annotations.py"
SPEC = importlib.util.spec_from_file_location("issue8_annotations", SCRIPT_PATH)
issue8_annotations = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = issue8_annotations
SPEC.loader.exec_module(issue8_annotations)


class Issue8ConfigAnnotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = {}
        with DATA_PATH.open(encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                if record["entry_id"] in TARGETS:
                    cls.entries[record["entry_id"]] = record

    def test_all_targets_share_the_expected_advisory_and_commit(self):
        self.assertEqual(set(self.entries), TARGETS)
        self.assertEqual(
            {entry["report_id"] for entry in self.entries.values()},
            {"GHSA-W7J5-J98M-W679"},
        )
        self.assertEqual(
            {entry["commit"] for entry in self.entries.values()},
            {"c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1"},
        )

    def test_fix_evidence_is_pinned_and_covers_missing_user_files(self):
        self.assertEqual(
            issue8_annotations.FIX_COMMIT,
            "84281abd4bd1c717bb37a2de12694fe203827eee",
        )
        self.assertEqual(
            issue8_annotations.MISSING_USER_FILES,
            {
                "scripts/e2e/Dockerfile",
                "scripts/e2e/Dockerfile.qr-import",
                "scripts/docker/install-sh-e2e/Dockerfile",
            },
        )
        self.assertEqual(
            issue8_annotations._user_directives(
                "# USER ignored\nRUN echo USER root\n  USER appuser\n"
            ),
            ["USER appuser"],
        )

    def test_semantic_rebuilds_remain_conservative(self):
        self.assertEqual(
            {entry["verify"] for entry in self.entries.values()},
            {0},
        )

    def test_inherited_root_entries_start_at_the_stage_boundary(self):
        for entry_id in ("entry-00241", "entry-00242", "entry-00243"):
            entry = self.entries[entry_id]
            self.assertEqual(entry["entry_point"]["line"], 1)
            self.assertTrue(entry["entry_point"]["code"].startswith("FROM "))
            self.assertIn("继承", entry["entry_point"]["desc"])

    def test_each_missing_user_entry_has_a_narrow_effective_operation(self):
        expected = {
            "entry-00241": ('CMD ["bash"]', 23),
            "entry-00242": ("RUN pnpm install --frozen-lockfile", 9),
            "entry-00243": (
                'ENTRYPOINT ["/usr/local/bin/openclaw-install-e2e"]',
                14,
            ),
        }
        for entry_id, (code, line) in expected.items():
            critical = self.entries[entry_id]["critical_operation"]
            self.assertEqual(critical["code"], code)
            self.assertEqual(critical["line"], line)

    def test_nonroot_variant_targets_the_explicit_sudoers_rule(self):
        entry = self.entries["entry-00244"]
        self.assertEqual(entry["entry_point"]["line"], "17-18")
        critical = entry["critical_operation"]
        self.assertEqual(critical["line"], 18)
        self.assertIn("NOPASSWD:ALL", critical["code"])
        self.assertNotIn("ENTRYPOINT", critical["code"])
        trace_text = "\n".join(node["code"] for node in entry["trace"])
        self.assertIn("USER app", trace_text)
        self.assertIn("RUN sudo chmod", trace_text)

    def test_traces_express_configuration_lifecycle_without_noise(self):
        for entry in self.entries.values():
            self.assertGreaterEqual(len(entry["trace"]), 2)
            self.assertLessEqual(len(entry["trace"]), 4)
            trace_text = "\n".join(node["code"] for node in entry["trace"])
            self.assertNotIn("WORKDIR", trace_text)
            self.assertNotIn("ENV ", trace_text)

    def test_diff_artifact_has_three_semantic_fields_per_entry(self):
        path = ROOT / "reports" / "issue-8-config-annotations.diff.csv"
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            self.assertEqual(
                reader.fieldnames,
                ["entry_id", "field", "before", "after", "reason"],
            )
            rows = list(reader)
        self.assertEqual({row["entry_id"] for row in rows}, TARGETS)
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(row["reason"] for row in rows))
        for entry_id in TARGETS:
            self.assertEqual(
                {row["field"] for row in rows if row["entry_id"] == entry_id},
                {"entry_point", "critical_operation", "trace"},
            )

    def test_dataset_shape_and_report_mapping_remain_valid(self):
        with DATA_PATH.open(encoding="utf-8") as handle:
            entries = [json.loads(line) for line in handle]
        reports_path = ROOT / "data" / "reports.jsonl"
        with reports_path.open(encoding="utf-8") as handle:
            reports = [json.loads(line) for line in handle]

        self.assertEqual(len(entries), 408)
        self.assertEqual(len(reports), 184)
        report_map = {report["report_id"]: report for report in reports}
        grouped: dict[str, list[str]] = {}
        for entry in entries:
            grouped.setdefault(entry["report_id"], []).append(entry["entry_id"])
        for report_id, report in report_map.items():
            self.assertEqual(report["entry_ids"], sorted(grouped[report_id]))

    def test_every_node_has_schema_compatible_shape(self):
        for entry in self.entries.values():
            for node in [
                entry["entry_point"],
                entry["critical_operation"],
                *entry["trace"],
            ]:
                self.assertEqual(set(node), {"code", "desc", "file", "line"})
                self.assertTrue(node["code"])
                self.assertTrue(node["desc"])
                if isinstance(node["line"], int):
                    self.assertGreaterEqual(node["line"], 1)
                else:
                    start, end = map(int, node["line"].split("-", 1))
                    self.assertGreaterEqual(start, 1)
                    self.assertGreaterEqual(end, start)


if __name__ == "__main__":
    unittest.main()
