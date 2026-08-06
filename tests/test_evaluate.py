import importlib.util
import json
import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
EVALUATE_PATH = REPO_ROOT / "examples" / "evaluate.py"


def load_evaluator():
    spec = importlib.util.spec_from_file_location("vulngym_evaluate", EVALUATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EndpointMatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluator = load_evaluator()

    def test_finding_inside_ground_truth_range_matches(self):
        finding = {
            "file": "service.py",
            "line": 112,
        }
        ground_truth = {
            "file": "service.py",
            "line": "112-119",
        }

        self.assertTrue(
            self.evaluator._endpoint_match(finding, ground_truth, tolerance=5)
        )

    def test_point_outside_range_uses_nearest_boundary_for_tolerance(self):
        ground_truth = {
            "file": "service.py",
            "line": "112-119",
        }

        self.assertTrue(
            self.evaluator._endpoint_match(
                {"file": "service.py", "line": 107},
                ground_truth,
                tolerance=5,
            )
        )
        self.assertFalse(
            self.evaluator._endpoint_match(
                {"file": "service.py", "line": 106},
                ground_truth,
                tolerance=5,
            )
        )

    def test_overlapping_ranges_match(self):
        self.assertTrue(
            self.evaluator._endpoint_match(
                {"file": "service.py", "line": "118-124"},
                {"file": "service.py", "line": "112-119"},
                tolerance=0,
            )
        )

    def test_invalid_line_values_do_not_match(self):
        ground_truth = {"file": "service.py", "line": "112-119"}
        for invalid_line in (0, "0", "119-112", "not-a-line"):
            with self.subTest(invalid_line=invalid_line):
                self.assertFalse(
                    self.evaluator._endpoint_match(
                        {"file": "service.py", "line": invalid_line},
                        ground_truth,
                        tolerance=5,
                    )
                )

    def test_existing_integer_matching_behavior_is_preserved(self):
        self.assertTrue(
            self.evaluator._endpoint_match(
                {"file": "service.py", "line": 100},
                {"file": "service.py", "line": 105},
                tolerance=5,
            )
        )
        self.assertFalse(
            self.evaluator._endpoint_match(
                {"file": "service.py", "line": 99},
                {"file": "service.py", "line": 105},
                tolerance=5,
            )
        )


class DatasetRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluator = load_evaluator()
        cls.entries = [
            json.loads(line)
            for line in (REPO_ROOT / "data" / "entries.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]

    def test_entry_00063_range_endpoint_is_matchable(self):
        entry = next(e for e in self.entries if e["entry_id"] == "entry-00063")
        finding = {
            "repo_url": entry["repo_url"],
            "commit": entry["commit"],
            "entry_point": {
                "file": entry["entry_point"]["file"],
                "line": 9,
            },
            "critical_operation": {
                "file": entry["critical_operation"]["file"],
                "line": 112,
            },
        }

        report = self.evaluator.evaluate(self.entries, [finding], tolerance=5)

        self.assertEqual(
            report["findings"][0]["matched_entry_ids"], ["entry-00063"]
        )


if __name__ == "__main__":
    unittest.main()
