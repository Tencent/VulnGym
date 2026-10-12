# -*- coding: utf-8 -*-
"""Tests for export_queue_for_49 fetch_failed filtering."""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
import export_queue_for_49 as eq  # noqa: E402


class TestExportQueue49(unittest.TestCase):
    def test_drops_fetch_failed(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            inp = td_path / "needs.csv"
            out = td_path / "for49.csv"
            rep = td_path / "report.json"
            with inp.open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=[
                        "entry_id",
                        "field_path",
                        "status",
                        "reason",
                    ],
                )
                w.writeheader()
                w.writerow(
                    {
                        "entry_id": "entry-00001",
                        "field_path": "entry_point",
                        "status": "needs_human",
                        "reason": "degenerate_snippet",
                    }
                )
                w.writerow(
                    {
                        "entry_id": "entry-00002",
                        "field_path": "critical_operation",
                        "status": "needs_human",
                        "reason": "repo_fetch_failed:git checkout ...",
                    }
                )
                w.writerow(
                    {
                        "entry_id": "entry-00003",
                        "field_path": "trace[0]",
                        "status": "needs_human",
                        "reason": "no_unique_match_in_file_or_missing_file",
                    }
                )
                w.writerow(
                    {
                        "entry_id": "entry-00004",
                        "field_path": "*",
                        "status": "needs_human",
                        "reason": "repo_fetch_failed:placeholder",
                    }
                )
            # monkeypatch via argv
            old = sys.argv
            try:
                sys.argv = [
                    "export_queue_for_49.py",
                    "--input",
                    str(inp),
                    "--output",
                    str(out),
                    "--report",
                    str(rep),
                ]
                self.assertEqual(eq.main(), 0)
            finally:
                sys.argv = old
            with out.open(encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            ids = {r["entry_id"] for r in rows}
            self.assertEqual(ids, {"entry-00001", "entry-00003"})
            self.assertTrue(all(r.get("node_path") == r.get("field_path") for r in rows))
            report = json.loads(rep.read_text(encoding="utf-8"))
            self.assertEqual(report["kept"], 2)
            self.assertEqual(report["dropped"], 2)
            self.assertEqual(report["dropped_reasons"].get("fetch_failed_excluded"), 1)
            self.assertEqual(report["dropped_reasons"].get("missing_id_or_path"), 1)


if __name__ == "__main__":
    unittest.main()
