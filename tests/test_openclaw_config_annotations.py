from __future__ import annotations

import csv
import json
import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_CACHE = Path(
    os.environ.get(
        "VULNGYM_OPENCLAW_SOURCE_CACHE",
        Path.home()
        / ".cache"
        / "vulngym"
        / "source-repos"
        / "openclaw--c56fb7f.git",
    )
)
VULNERABLE_COMMIT = "c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1"
FIX_COMMIT = "84281abd4bd1c717bb37a2de12694fe203827eee"

EXPECTED_NODES = {
    "entry-00241": {
        "entry_point": ("scripts/e2e/Dockerfile", 1),
        "critical_operation": ("scripts/e2e/Dockerfile", 23),
        "trace": [
            ("scripts/e2e/Dockerfile", 1),
            ("scripts/e2e/Dockerfile", 19),
            ("scripts/e2e/Dockerfile", 23),
        ],
    },
    "entry-00242": {
        "entry_point": ("scripts/e2e/Dockerfile.qr-import", 1),
        "critical_operation": ("scripts/e2e/Dockerfile.qr-import", 9),
        "trace": [
            ("scripts/e2e/Dockerfile.qr-import", 1),
            ("scripts/e2e/Dockerfile.qr-import", 9),
        ],
    },
    "entry-00243": {
        "entry_point": ("scripts/docker/install-sh-e2e/Dockerfile", 1),
        "critical_operation": ("scripts/docker/install-sh-e2e/Dockerfile", 14),
        "trace": [
            ("scripts/docker/install-sh-e2e/Dockerfile", 1),
            ("scripts/docker/install-sh-e2e/Dockerfile", 11),
            ("scripts/docker/install-sh-e2e/Dockerfile", 14),
        ],
    },
    "entry-00244": {
        "entry_point": ("scripts/docker/install-sh-nonroot/Dockerfile", 17),
        "critical_operation": (
            "scripts/docker/install-sh-nonroot/Dockerfile",
            18,
        ),
        "trace": [
            ("scripts/docker/install-sh-nonroot/Dockerfile", 17),
            ("scripts/docker/install-sh-nonroot/Dockerfile", 18),
            ("scripts/docker/install-sh-nonroot/Dockerfile", 20),
            ("scripts/docker/install-sh-nonroot/Dockerfile", 27),
            ("scripts/docker/install-sh-nonroot/Dockerfile", 29),
        ],
    },
}

MISSING_USER_FILES = {
    "scripts/e2e/Dockerfile",
    "scripts/e2e/Dockerfile.qr-import",
    "scripts/docker/install-sh-e2e/Dockerfile",
}


def load_entries(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8") as stream:
        entries = [json.loads(line) for line in stream]
    return {entry["entry_id"]: entry for entry in entries}


def location(node: dict) -> tuple[str, int | str]:
    return node["file"], node["line"]


def line_bounds(line: int | str) -> tuple[int, int]:
    if isinstance(line, int):
        return line, line
    start, end = line.split("-", 1)
    return int(start), int(end)


def iter_nodes(entry: dict):
    yield entry["entry_point"]
    yield entry["critical_operation"]
    yield from entry["trace"]


def git_show(commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", f"--git-dir={SOURCE_CACHE}", "show", f"{commit}:{path}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def cache_has_commit(commit: str) -> bool:
    if not SOURCE_CACHE.exists():
        return False
    result = subprocess.run(
        ["git", f"--git-dir={SOURCE_CACHE}", "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
    )
    return result.returncode == 0


class OpenClawConfigAnnotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = load_entries(REPO_ROOT / "data" / "entries.jsonl")

    def test_expected_entry_points_critical_operations_and_traces(self) -> None:
        for entry_id, expected in EXPECTED_NODES.items():
            with self.subTest(entry_id=entry_id):
                entry = self.entries[entry_id]
                self.assertEqual(entry["commit"], VULNERABLE_COMMIT)
                self.assertEqual(entry["verify"], 0)
                self.assertEqual(location(entry["entry_point"]), expected["entry_point"])
                self.assertEqual(
                    location(entry["critical_operation"]),
                    expected["critical_operation"],
                )
                self.assertEqual(
                    [location(node) for node in entry["trace"]],
                    expected["trace"],
                )

    def test_descriptions_explain_configuration_semantics(self) -> None:
        expected_terms = {
            "entry-00241": ("USER", "uid 0"),
            "entry-00242": ("USER", "root"),
            "entry-00243": ("USER", "uid 0"),
            "entry-00244": ("非 root", "NOPASSWD:ALL"),
        }
        for entry_id, (entry_term, critical_term) in expected_terms.items():
            with self.subTest(entry_id=entry_id):
                entry = self.entries[entry_id]
                self.assertIn(entry_term, entry["entry_point"]["desc"])
                self.assertIn(critical_term, entry["critical_operation"]["desc"])
                self.assertTrue(all(node.get("desc") for node in iter_nodes(entry)))

    def test_review_csv_has_three_semantic_fields_per_entry(self) -> None:
        with (REPO_ROOT / "config_vuln_fix_diff.csv").open(
            encoding="utf-8", newline=""
        ) as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 12)
        self.assertEqual({row["entry_id"] for row in rows}, set(EXPECTED_NODES))
        for entry_id in EXPECTED_NODES:
            fields = {row["field"] for row in rows if row["entry_id"] == entry_id}
            self.assertEqual(fields, {"entry_point", "critical_operation", "trace"})

    def test_annotation_guide_records_compatibility_and_evidence(self) -> None:
        guide = (REPO_ROOT / "config_vuln_annotation.md").read_text(encoding="utf-8")
        for term in (
            "配置状态的引入或声明",
            "不修改 `SCHEMA.md`",
            VULNERABLE_COMMIT,
            FIX_COMMIT,
            "保持 `verify: 0`",
        ):
            self.assertIn(term, guide)

    def test_all_annotated_nodes_match_vulnerable_source(self) -> None:
        if not cache_has_commit(VULNERABLE_COMMIT):
            self.skipTest(f"OpenClaw source cache unavailable: {SOURCE_CACHE}")

        source_files: dict[str, list[str]] = {}
        matched_nodes = 0
        for entry_id in EXPECTED_NODES:
            entry = self.entries[entry_id]
            for node in iter_nodes(entry):
                path = node["file"]
                if path not in source_files:
                    source_files[path] = git_show(VULNERABLE_COMMIT, path).splitlines()
                start, end = line_bounds(node["line"])
                actual = "\n".join(source_files[path][start - 1 : end])
                with self.subTest(entry_id=entry_id, file=path, line=node["line"]):
                    self.assertEqual(actual, node["code"])
                matched_nodes += 1

        self.assertEqual(matched_nodes, 21)
        for path in MISSING_USER_FILES:
            instructions = [
                line.strip()
                for line in source_files[path]
                if line.strip() and not line.lstrip().startswith("#")
            ]
            self.assertFalse(any(line.startswith("USER ") for line in instructions))

    def test_fix_commit_adds_non_root_runtime_users(self) -> None:
        if not cache_has_commit(FIX_COMMIT):
            self.skipTest(f"OpenClaw fix commit unavailable: {SOURCE_CACHE}")
        for path in MISSING_USER_FILES:
            with self.subTest(path=path):
                fixed_source = git_show(FIX_COMMIT, path)
                self.assertIn("USER appuser", fixed_source)


if __name__ == "__main__":
    unittest.main()
