from __future__ import annotations

import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "trace_review_plan.py"
SPEC = importlib.util.spec_from_file_location("trace_review_plan", SCRIPT)
assert SPEC and SPEC.loader
review = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = review
SPEC.loader.exec_module(review)


def node(
    name: str,
    line: int | str,
    *,
    file: str = "app.py",
    desc: str = "",
) -> dict:
    value = {"file": file, "line": line, "code": name}
    if desc:
        value["desc"] = desc
    return value


def entry(trace: list[dict], *, verify: int = 0, entry_id: str = "entry-test") -> dict:
    return {
        "entry_id": entry_id,
        "report_id": "GHSA-TEST-TEST-TEST",
        "source_link": "https://github.com/advisories/GHSA-TEST-TEST-TEST",
        "vuln_ids": [],
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "test",
        "repo_url": "https://github.com/example/test",
        "commit": "a" * 40,
        "vuln_title": "test",
        "vuln_category_l1": "test",
        "vuln_category_l2": "test",
        "entry_point": node("entry", 10),
        "critical_operation": node("sink", 30),
        "trace": trace,
        "verify": verify,
    }


def write_entries(path: Path, entries: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
            for value in entries
        ),
        encoding="utf-8",
    )


def read_plan(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_plan(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=review.PLAN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def decide_all(path: Path, decision: str) -> list[dict[str, str]]:
    rows = read_plan(path)
    for row in rows:
        row["decision"] = decision
        row["reviewer"] = "reviewer"
        row["rationale"] = "checked against the original trace"
    write_plan(path, rows)
    return rows


class DetectionTests(unittest.TestCase):
    def test_line_span_supports_integer_and_range(self) -> None:
        self.assertEqual(review.line_span(7), (7, 7))
        self.assertEqual(review.line_span("7-11"), (7, 11))
        with self.assertRaises(review.ReviewPlanError):
            review.line_span("11-7")

    def test_duplicate_description_controls_suggestion(self) -> None:
        exact = node("repeat", 20, desc="same stage")
        conflict = node("other", 21, desc="first stage")
        value = entry(
            [
                exact,
                dict(exact),
                conflict,
                {**conflict, "desc": "second stage"},
            ]
        )
        rows, report = review.detect_candidates([value], "d" * 64)

        duplicates = [row for row in rows if "duplicate" in row["candidate_types"]]
        self.assertEqual(len(duplicates), 2)
        self.assertEqual(duplicates[0]["candidate_types"], "duplicate_exact")
        self.assertEqual(duplicates[0]["suggested_decision"], "remove")
        self.assertEqual(
            duplicates[1]["candidate_types"],
            "duplicate_desc_conflict",
        )
        self.assertEqual(duplicates[1]["suggested_decision"], "keep")
        self.assertEqual(report["duplicate_exact"], 1)
        self.assertEqual(report["duplicate_desc_conflicts"], 1)

    def test_boundaries_use_closed_ranges_and_skip_cross_file(self) -> None:
        value = entry(
            [
                node("before", "1-9"),
                node("overlaps entry", "9-10"),
                node("after", 31),
                node("cross", 999, file="other.py"),
            ]
        )
        rows, report = review.detect_candidates([value], "d" * 64)

        self.assertEqual([row["trace_index"] for row in rows], ["0", "2"])
        self.assertEqual(rows[0]["candidate_types"], "before_entry")
        self.assertEqual(rows[1]["candidate_types"], "after_critical")
        self.assertEqual(report["cross_file_skipped"], 1)

    def test_event_id_is_stable(self) -> None:
        repeated = node("repeat", 20, desc="same")
        value = entry([repeated, dict(repeated)])
        first, _ = review.detect_candidates([value], "a" * 64)
        second, _ = review.detect_candidates([value], "b" * 64)

        self.assertEqual(first[0]["event_id"], second[0]["event_id"])
        self.assertNotEqual(first[0]["dataset_sha256"], second[0]["dataset_sha256"])


class RoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.input = self.root / "entries.jsonl"
        self.plan = self.root / "plan.csv"
        self.report = self.root / "report.json"
        self.output = self.root / "output.jsonl"
        self.diff = self.root / "diff.csv"
        self.audit = self.root / "audit.csv"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, entries: list[dict]) -> dict[str, object]:
        write_entries(self.input, entries)
        return review.create_plan(self.input, self.plan, self.report)

    def apply(self, **kwargs: object) -> dict[str, int]:
        return review.apply_plan(
            self.input,
            self.plan,
            self.output,
            self.diff,
            self.audit,
            **kwargs,
        )

    def test_plan_is_byte_deterministic(self) -> None:
        repeated = node("repeat", 20, desc="same")
        self.create([entry([repeated, dict(repeated)])])
        first = self.plan.read_bytes()
        review.create_plan(self.input, self.plan, self.report)
        self.assertEqual(self.plan.read_bytes(), first)

    def test_apply_uses_original_indices_without_shift(self) -> None:
        one = node("one", 20, desc="same")
        two = node("two", 21, desc="same")
        self.create([entry([one, dict(one), two, dict(two)])])
        decide_all(self.plan, "remove")

        result = self.apply()
        output = json.loads(self.output.read_text(encoding="utf-8"))
        diff = read_plan(self.diff)

        self.assertEqual(output["trace"], [one, two])
        self.assertEqual(result["removed"], 2)
        self.assertEqual(
            [row["original_trace_index"] for row in diff],
            ["1", "3"],
        )

    def test_keep_and_pending_preserve_trace(self) -> None:
        repeated = node("repeat", 20, desc="same")
        original = entry([repeated, dict(repeated)])
        self.create([original])

        with self.assertRaises(review.ReviewPlanError):
            self.apply()

        result = self.apply(allow_pending=True)
        output = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(output["trace"], original["trace"])
        self.assertEqual(self.output.read_bytes(), self.input.read_bytes())
        self.assertEqual(result["pending"], 1)

    def test_stale_entry_fails_before_outputs(self) -> None:
        repeated = node("repeat", 20, desc="same")
        value = entry([repeated, dict(repeated)])
        self.create([value])
        decide_all(self.plan, "remove")
        value["trace"][0]["desc"] = "changed after review"
        write_entries(self.input, [value])

        with self.assertRaises(review.ReviewPlanError):
            self.apply()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.diff.exists())
        self.assertFalse(self.audit.exists())

    def test_verified_removal_requires_explicit_flag(self) -> None:
        repeated = node("repeat", 20, desc="same")
        self.create([entry([repeated, dict(repeated)], verify=1)])
        decide_all(self.plan, "remove")

        with self.assertRaisesRegex(review.ReviewPlanError, "verify=1"):
            self.apply()
        result = self.apply(include_verified=True)
        self.assertEqual(result["removed"], 1)

    def test_reviewer_and_rationale_are_required(self) -> None:
        repeated = node("repeat", 20, desc="same")
        self.create([entry([repeated, dict(repeated)])])
        rows = read_plan(self.plan)
        rows[0]["decision"] = "keep"
        write_plan(self.plan, rows)

        with self.assertRaisesRegex(review.ReviewPlanError, "reviewer"):
            self.apply()

    def test_incomplete_and_tampered_plans_fail(self) -> None:
        one = node("one", 20, desc="same")
        two = node("two", 21, desc="same")
        self.create([entry([one, dict(one), two, dict(two)])])
        rows = decide_all(self.plan, "keep")

        write_plan(self.plan, rows[:-1])
        with self.assertRaisesRegex(review.ReviewPlanError, "incomplete or stale"):
            self.apply()

        rows[0]["candidate_types"] = "after_critical"
        write_plan(self.plan, rows)
        with self.assertRaisesRegex(review.ReviewPlanError, "immutable field"):
            self.apply()

    def test_output_paths_cannot_overwrite_inputs(self) -> None:
        repeated = node("repeat", 20, desc="same")
        self.create([entry([repeated, dict(repeated)])])
        with self.assertRaisesRegex(review.ReviewPlanError, "distinct"):
            review.apply_plan(
                self.input,
                self.plan,
                self.input,
                self.diff,
                self.audit,
                allow_pending=True,
            )


class DatasetRegressionTests(unittest.TestCase):
    def test_v014_duplicates_are_distinct_recurrence_descriptions(self) -> None:
        dataset = Path(__file__).resolve().parents[1] / "data" / "entries.jsonl"
        entries = review.load_entries(dataset)
        rows, report = review.detect_candidates(entries, review.file_sha256(dataset))
        duplicates = [row for row in rows if "duplicate" in row["candidate_types"]]

        self.assertEqual(report["entries_scanned"], 408)
        self.assertEqual(report["trace_nodes_scanned"], 2073)
        self.assertEqual(report["duplicate_candidates"], 7)
        self.assertEqual(report["duplicate_exact"], 0)
        self.assertEqual(report["duplicate_desc_conflicts"], 7)
        self.assertEqual(len(duplicates), 7)


if __name__ == "__main__":
    unittest.main()
