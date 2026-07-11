from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from trace_cleanup import (  # noqa: E402
    DataValidationError,
    load_jsonl,
    parse_line,
    process_entries,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def node(file: str, line: int | str, code: str, desc: str | None = None) -> dict:
    value = {"file": file, "line": line, "code": code}
    if desc is not None:
        value["desc"] = desc
    return value


def entry(trace: list[dict]) -> dict:
    return {
        "commit": "a" * 40,
        "critical_operation": node("a.py", "20-22", "sink()"),
        "entry_id": "entry-00001",
        "entry_point": node("a.py", 10, "source()"),
        "repo_url": "https://github.com/example/project",
        "trace": trace,
        "verify": 0,
    }


class ParseLineTests(unittest.TestCase):
    def test_accepts_integer_and_range(self) -> None:
        self.assertEqual(parse_line(7), (7, 7))
        self.assertEqual(parse_line("7-9"), (7, 9))

    def test_rejects_invalid_values(self) -> None:
        for value in (0, True, "0-2", "9-7", "7", None):
            with self.subTest(value=value), self.assertRaises(DataValidationError):
                parse_line(value)


class ProcessingTests(unittest.TestCase):
    def test_report_mode_does_not_modify_input(self) -> None:
        original = entry([node("a.py", 5, "early()")])
        snapshot = copy.deepcopy(original)
        output, events, report = process_entries([original], mode="report")

        self.assertEqual(original, snapshot)
        self.assertEqual(output, [snapshot])
        self.assertEqual(events[0]["kind"], "before_entry_point")
        self.assertEqual(report["removed_nodes"], 0)

    def test_fix_removes_nodes_outside_same_file_boundaries(self) -> None:
        original = entry(
            [
                node("a.py", "8-9", "early()"),
                node("a.py", "10-12", "overlaps source"),
                node("a.py", 23, "late()"),
            ]
        )
        output, _, report = process_entries([original], mode="fix")

        self.assertEqual([item["code"] for item in output[0]["trace"]], ["overlaps source"])
        self.assertEqual(report["removed_nodes"], 2)

    def test_cross_file_nodes_are_kept_and_logged(self) -> None:
        original = entry([node("b.py", 1, "other()")])
        output, events, _ = process_entries([original], mode="fix")

        self.assertEqual(output[0]["trace"], original["trace"])
        self.assertEqual([event["kind"] for event in events], ["cross_file_skipped"])
        self.assertEqual(events[0]["details"]["boundaries"], ["entry_point", "critical_operation"])

    def test_duplicate_with_same_desc_keeps_first(self) -> None:
        duplicate = node("a.py", 15, "step()", "same")
        original = entry([duplicate, copy.deepcopy(duplicate)])
        output, events, report = process_entries([original], mode="fix")

        self.assertEqual(output[0]["trace"], [duplicate])
        self.assertEqual(events[0]["kind"], "duplicate")
        self.assertEqual(report["removed_nodes"], 1)


    def test_duplicate_syncs_the_only_description(self) -> None:
        original = entry([node("a.py", 15, "step()"), node("a.py", 15, "step()", "detail")])
        output, events, _ = process_entries([original], mode="fix")

        self.assertEqual(output[0]["trace"], [node("a.py", 15, "step()", "detail")])
        self.assertEqual([event["kind"] for event in events[:2]], ["desc_sync", "duplicate"])

    def test_duplicate_desc_conflict_is_kept_for_review(self) -> None:
        original = entry(
            [node("a.py", 15, "step()", "first"), node("a.py", 15, "step()", "second")]
        )
        output, events, report = process_entries([original], mode="fix")

        self.assertEqual(output[0]["trace"], original["trace"])
        self.assertEqual(events[0]["kind"], "duplicate_desc_conflict")
        self.assertEqual(report["manual_review_nodes"], 2)
        self.assertEqual(report["duplicate_candidate_groups"], 1)
        self.assertEqual(report["duplicate_candidate_nodes"], 1)
        self.assertEqual(report["duplicate_desc_conflict_groups"], 1)

    def test_duplicate_desc_conflict_can_be_forced(self) -> None:
        original = entry(
            [node("a.py", 15, "step()", "first"), node("a.py", 15, "step()", "second")]
        )
        output, _, report = process_entries(
            [original], mode="fix", dedupe_desc_conflicts=True
        )

        self.assertEqual(output[0]["trace"], [original["trace"][0]])
        self.assertEqual(report["removed_nodes"], 1)

    def test_fix_protects_verified_entries_by_default(self) -> None:
        original = entry([node("a.py", 5, "early()")])
        original["verify"] = 1
        output, events, report = process_entries([original], mode="fix")

        self.assertEqual(output[0]["trace"], original["trace"])
        self.assertEqual(events[0]["action"], "kept_for_review")
        self.assertEqual(report["removed_nodes"], 0)
        self.assertEqual(report["manual_review_nodes"], 1)

    def test_fix_verified_requires_explicit_opt_in(self) -> None:
        original = entry([node("a.py", 5, "early()")])
        original["verify"] = 1
        output, _, report = process_entries([original], mode="fix", fix_verified=True)

        self.assertEqual(output[0]["trace"], [])
        self.assertEqual(report["removed_nodes"], 1)


class DatasetRegressionTests(unittest.TestCase):
    def test_committed_output_is_reproducible_from_real_dataset(self) -> None:
        source = load_jsonl(REPO_ROOT / "data" / "entries.jsonl")
        committed = load_jsonl(REPO_ROOT / "data" / "entries.trace_fixed.jsonl")
        expected_report = json.loads(
            (REPO_ROOT / "trace_fix_report.json").read_text(encoding="utf-8")
        )

        output, events, report = process_entries(source, mode="fix")
        removed = {
            (event["entry_id"], event["field_path"], event["kind"])
            for event in events
            if event["action"] == "removed"
        }

        self.assertEqual(output, committed)
        self.assertEqual(report, expected_report)
        self.assertEqual(
            removed,
            {
                ("entry-00103", "trace[1]", "before_entry_point"),
                ("entry-00185", "trace[2]", "after_critical_operation"),
                ("entry-00320", "trace[2]", "before_entry_point"),
                ("entry-00511", "trace[4]", "after_critical_operation"),
            },
        )

        unverified = [entry for entry in committed if entry["verify"] == 0]
        _, _, recheck = process_entries(unverified, mode="report")
        self.assertEqual(recheck["order_anomalies"], 0)


if __name__ == "__main__":
    unittest.main()
