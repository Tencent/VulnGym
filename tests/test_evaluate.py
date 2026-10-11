from __future__ import annotations

import unittest
from pathlib import Path

from examples.evaluate import (
    _endpoint_match,
    evaluate,
    line_span_distance,
    load_jsonl,
    normalize_line_span,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


class LineSpanTests(unittest.TestCase):
    def test_normalizes_integer_and_range_locations(self) -> None:
        self.assertEqual(normalize_line_span(12), (12, 12))
        self.assertEqual(normalize_line_span("12"), (12, 12))
        self.assertEqual(normalize_line_span("12-19"), (12, 19))

    def test_rejects_invalid_locations(self) -> None:
        for value in (None, True, 0, -1, "0", "19-12", "12-", "a-b"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_line_span(value))

    def test_span_distance_uses_nearest_endpoints(self) -> None:
        self.assertEqual(line_span_distance((10, 15), (12, 20)), 0)
        self.assertEqual(line_span_distance((10, 15), (18, 20)), 3)
        self.assertEqual(line_span_distance((18, 20), (10, 15)), 3)


class EndpointMatchTests(unittest.TestCase):
    def test_integer_finding_matches_ground_truth_range(self) -> None:
        ground_truth = {"file": "src/example.py", "line": "112-119"}
        self.assertTrue(
            _endpoint_match(
                {"file": "./src/example.py", "line": 119},
                ground_truth,
                tolerance=0,
            )
        )
        self.assertTrue(
            _endpoint_match(
                {"file": "src/example.py", "line": 124},
                ground_truth,
                tolerance=5,
            )
        )
        self.assertFalse(
            _endpoint_match(
                {"file": "src/example.py", "line": 125},
                ground_truth,
                tolerance=5,
            )
        )

    def test_range_finding_matches_overlapping_ground_truth_range(self) -> None:
        self.assertTrue(
            _endpoint_match(
                {"file": "src/example.py", "line": "108-113"},
                {"file": "src/example.py", "line": "112-119"},
                tolerance=0,
            )
        )


class EvaluationTests(unittest.TestCase):
    def test_range_endpoints_are_usable_and_matchable(self) -> None:
        entry = {
            "entry_id": "entry-test",
            "report_id": "GHSA-TEST-TEST-TEST",
            "repo_url": "https://github.com/example/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/source.py", "line": "10-12"},
            "critical_operation": {"file": "src/sink.py", "line": "30-35"},
        }
        finding = {
            "repo_url": entry["repo_url"],
            "commit": entry["commit"],
            "entry_point": {"file": "src/source.py", "line": 11},
            "critical_operation": {"file": "src/sink.py", "line": 35},
        }

        report = evaluate([entry], [finding], tolerance=0)

        self.assertEqual(report["totals"]["usable_entries"], 1)
        self.assertEqual(report["totals"]["skipped_entries_invalid_line"], 0)
        self.assertEqual(report["recall"]["entry_level"]["numerator"], 1)
        self.assertEqual(report["findings"][0]["matched_entry_ids"], ["entry-test"])

    def test_invalid_ground_truth_locations_are_skipped(self) -> None:
        entry = {
            "entry_id": "entry-invalid",
            "report_id": "GHSA-TEST-TEST-TEST",
            "repo_url": "https://github.com/example/project",
            "commit": "a" * 40,
            "entry_point": {"file": "src/source.py", "line": 0},
            "critical_operation": {"file": "src/sink.py", "line": 35},
        }

        report = evaluate([entry], [], tolerance=5)

        self.assertEqual(report["totals"]["usable_entries"], 0)
        self.assertEqual(report["totals"]["skipped_entries_invalid_line"], 1)
        self.assertEqual(report["totals"]["skipped_entries_line_zero"], 1)

    def test_current_dataset_self_matches_at_zero_tolerance(self) -> None:
        entries = load_jsonl(REPO_ROOT / "data" / "entries.jsonl")
        findings = [
            {
                "repo_url": entry["repo_url"],
                "commit": entry["commit"],
                "entry_point": {
                    "file": entry["entry_point"]["file"],
                    "line": entry["entry_point"]["line"],
                },
                "critical_operation": {
                    "file": entry["critical_operation"]["file"],
                    "line": entry["critical_operation"]["line"],
                },
            }
            for entry in entries
        ]

        report = evaluate(entries, findings, tolerance=0)

        self.assertEqual(report["totals"]["skipped_entries_invalid_line"], 0)
        self.assertEqual(report["recall"]["entry_level"]["numerator"], len(entries))
        self.assertEqual(report["recall"]["entry_level"]["denominator"], len(entries))


if __name__ == "__main__":
    unittest.main()
