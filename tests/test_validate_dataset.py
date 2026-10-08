from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from examples.validate_dataset import validate_dataset


REPO_ROOT = Path(__file__).resolve().parent.parent


def valid_entry(entry_id: str = "entry-00001") -> dict:
    return {
        "commit": "a" * 40,
        "critical_operation": {
            "code": "sink(value)",
            "desc": "Writes the validated value.",
            "file": "src/sink.py",
            "line": "20-22",
        },
        "entry_id": entry_id,
        "entry_point": {
            "code": "value = request.data",
            "desc": "Reads caller-controlled input.",
            "file": "src/source.py",
            "line": 10,
        },
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "example",
        "repo_url": "https://github.com/example/project",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "trace": [],
        "verify": 1,
        "vuln_category_l1": "Injection",
        "vuln_category_l2": "Example",
        "vuln_ids": ["CVE-2026-0001", "GHSA-AAAA-BBBB-CCCC"],
        "vuln_title": "Example vulnerability",
    }


def valid_report(entry_ids: list[str] | None = None) -> dict:
    entry_ids = entry_ids or ["entry-00001"]
    return {
        "commit": "a" * 40,
        "entry_ids": entry_ids,
        "num_entries": len(entry_ids),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "example",
        "repo_url": "https://github.com/example/project",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "vuln_ids": ["CVE-2026-0001", "GHSA-AAAA-BBBB-CCCC"],
        "vuln_title": "Example vulnerability",
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            json.dump(row, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")


class DatasetValidationTests(unittest.TestCase):
    def validate_rows(self, entries: list[dict], reports: list[dict]):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries_path = root / "entries.jsonl"
            reports_path = root / "reports.jsonl"
            write_jsonl(entries_path, entries)
            write_jsonl(reports_path, reports)
            return validate_dataset(entries_path, reports_path)

    def test_minimal_valid_dataset_passes(self) -> None:
        result = self.validate_rows([valid_entry()], [valid_report()])

        self.assertTrue(result.ok)
        self.assertEqual(result.stats["entries"], 1)
        self.assertEqual(result.stats["reports"], 1)
        self.assertEqual(result.stats["range_node_locations"], 1)

    def test_current_release_satisfies_documented_invariants(self) -> None:
        result = validate_dataset(
            REPO_ROOT / "data" / "entries.jsonl",
            REPO_ROOT / "data" / "reports.jsonl",
        )

        self.assertTrue(result.ok, "\n".join(item.render() for item in result.diagnostics))
        self.assertEqual(result.stats["entries"], 408)
        self.assertEqual(result.stats["reports"], 184)
        self.assertEqual(result.stats["linked_advisories"], 184)

    def test_detects_report_join_mismatches(self) -> None:
        report = valid_report()
        report["entry_ids"] = ["entry-00002"]
        report["num_entries"] = 2

        result = self.validate_rows([valid_entry()], [report])
        codes = {item.code for item in result.diagnostics}

        self.assertIn("REPORT_ENTRY_IDS_MISMATCH", codes)
        self.assertIn("REPORT_NUM_ENTRIES_MISMATCH", codes)

    def test_detects_invalid_range_and_text_damage(self) -> None:
        entry = valid_entry()
        entry["critical_operation"]["line"] = "22-20"
        entry["critical_operation"]["desc"] = "配置?写入"

        result = self.validate_rows([entry], [valid_report()])
        codes = {item.code for item in result.diagnostics}

        self.assertIn("NODE_LINE_INVALID", codes)
        self.assertIn("TEXT_SUSPICIOUS_QUESTION_MARK", codes)

    def test_detects_duplicate_ids(self) -> None:
        first = valid_entry("entry-00002")
        second = copy.deepcopy(first)
        report = valid_report(["entry-00002"])

        result = self.validate_rows([first, second], [report])
        codes = {item.code for item in result.diagnostics}

        self.assertIn("ROW_DUPLICATE_ID", codes)

    def test_detects_unstable_entry_order(self) -> None:
        second = valid_entry("entry-00002")
        first = valid_entry("entry-00001")
        report = valid_report(["entry-00001", "entry-00002"])

        result = self.validate_rows([second, first], [report])

        self.assertIn("ROW_ORDER", {item.code for item in result.diagnostics})

    def test_detects_canonical_report_metadata_drift(self) -> None:
        report = valid_report()
        report["commit"] = "b" * 40

        result = self.validate_rows([valid_entry()], [report])

        self.assertIn(
            "REPORT_CANONICAL_MISMATCH",
            {item.code for item in result.diagnostics},
        )


if __name__ == "__main__":
    unittest.main()
