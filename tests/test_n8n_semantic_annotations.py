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
        "VULNGYM_N8N_SOURCE_CACHE",
        Path.home()
        / ".cache"
        / "vulngym"
        / "source-repos"
        / "n8n-io--n8n--c37165a31c.git",
    )
)

EXPECTED_NODES = {
    "entry-00099": {
        "entry_point": (
            "packages/cli/src/workflows/workflows.controller.ts",
            "561-565",
        ),
        "critical_operation": (
            "packages/workflow/src/expression-evaluator-proxy.ts",
            20,
        ),
        "trace": [
            ("packages/cli/src/workflows/workflows.controller.ts", "561-565"),
            ("packages/workflow/src/expression.ts", "368-393"),
            ("packages/workflow/src/expression.ts", "451-453"),
            ("packages/workflow/src/expression-evaluator-proxy.ts", "9-13"),
            ("packages/workflow/src/expression-sandboxing.ts", "264-267"),
            ("packages/workflow/src/expression-evaluator-proxy.ts", 20),
        ],
    },
    "entry-00100": {
        "entry_point": ("packages/workflow/src/expression.ts", "368-382"),
        "critical_operation": (
            "packages/workflow/src/expression-sandboxing.ts",
            "288-299",
        ),
        "trace": [
            ("packages/workflow/src/expression.ts", "368-382"),
            ("packages/workflow/src/expression.ts", "434-438"),
            ("packages/workflow/src/expression.ts", "451-453"),
            ("packages/workflow/src/expression-evaluator-proxy.ts", "9-13"),
            ("packages/workflow/src/expression-sandboxing.ts", "288-299"),
            ("packages/workflow/src/expression-evaluator-proxy.ts", 20),
        ],
    },
    "entry-00103": {
        "entry_point": (
            "packages/cli/src/webhooks/webhook-helpers.ts",
            "882-892",
        ),
        "critical_operation": (
            "packages/cli/src/webhooks/webhook-request-handler.ts",
            "153-157",
        ),
        "trace": [
            ("packages/cli/src/webhooks/webhook-helpers.ts", "882-892"),
            ("packages/cli/src/webhooks/webhook-helpers.ts", "559-562"),
            ("packages/cli/src/webhooks/webhook-request-handler.ts", "65-76"),
            ("packages/cli/src/webhooks/webhook-request-handler.ts", "127-131"),
            ("packages/cli/src/webhooks/webhook-request-handler.ts", "146-150"),
            ("packages/core/src/html-sandbox.ts", "19-25"),
            ("packages/cli/src/webhooks/webhook-request-handler.ts", "153-157"),
        ],
    },
    "entry-00176": {
        "entry_point": ("packages/nodes-base/nodes/Code/Code.node.ts", 206),
        "critical_operation": (
            "packages/@n8n/task-runner-python/src/task_executor.py",
            213,
        ),
        "trace": [
            ("packages/nodes-base/nodes/Code/Code.node.ts", "206-209"),
            (
                "packages/nodes-base/nodes/Code/PythonTaskRunnerSandbox.ts",
                "50-66",
            ),
            ("packages/@n8n/task-runner-python/src/task_runner.py", "321-329"),
            ("packages/@n8n/task-runner-python/src/task_analyzer.py", "63-76"),
            ("packages/@n8n/task-runner-python/src/task_executor.py", "203-213"),
        ],
    },
    "entry-00511": {
        "entry_point": ("packages/workflow/src/expression.ts", "451-465"),
        "critical_operation": (
            "packages/@n8n/expression-runtime/src/extensions/extend.ts",
            "132-134",
        ),
        "trace": [
            ("packages/workflow/src/expression.ts", "451-465"),
            ("packages/workflow/src/expression.ts", "484-492"),
            ("packages/workflow/src/expression.ts", "505-507"),
            ("packages/workflow/src/expression.ts", "524-536"),
            ("packages/@n8n/expression-runtime/src/runtime/reset.ts", "165-168"),
            (
                "packages/@n8n/expression-runtime/src/extensions/extend.ts",
                "105-106",
            ),
            (
                "packages/@n8n/expression-runtime/src/extensions/extend.ts",
                "79-85",
            ),
            (
                "packages/@n8n/expression-runtime/src/extensions/extend.ts",
                "132-134",
            ),
        ],
    },
    "entry-00512": {
        "entry_point": ("packages/workflow/src/expression.ts", "451-465"),
        "critical_operation": (
            "packages/@n8n/expression-runtime/src/runtime/reset.ts",
            "41-46",
        ),
        "trace": [
            ("packages/workflow/src/expression.ts", "451-465"),
            ("packages/workflow/src/expression.ts", "505-507"),
            ("packages/workflow/src/expression-sandboxing.ts", "493-504"),
            (
                "packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts",
                "454-470",
            ),
            ("packages/@n8n/expression-runtime/src/runtime/reset.ts", "41-46"),
            (
                "packages/@n8n/expression-runtime/src/bridge/isolated-vm-bridge.ts",
                "482-486",
            ),
        ],
    },
}

KNOWN_BAD_ANCHORS = {
    "entry-00099": (
        "critical_operation",
        "packages/workflow/src/expression-sandboxing.ts",
        244,
    ),
    "entry-00100": (
        "critical_operation",
        "packages/workflow/src/expression-sandboxing.ts",
        "330-336",
    ),
    "entry-00103": (
        "entry_point",
        "packages/cli/src/webhooks/webhook-helpers.ts",
        615,
    ),
    "entry-00176": (
        "critical_operation",
        "packages/@n8n/task-runner-python/src/constants.py",
        126,
    ),
    "entry-00511": ("entry_point", "packages/workflow/src/expression.ts", 485),
    "entry-00512": ("entry_point", "packages/workflow/src/expression.ts", 524),
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


class N8nSemanticAnnotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = load_entries(REPO_ROOT / "data" / "entries.jsonl")

    def test_expected_entry_points_critical_operations_and_traces(self) -> None:
        self.assertEqual(set(EXPECTED_NODES), set(KNOWN_BAD_ANCHORS))
        for entry_id, expected in EXPECTED_NODES.items():
            with self.subTest(entry_id=entry_id):
                entry = self.entries[entry_id]
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

    def test_known_bad_anchors_do_not_return(self) -> None:
        for entry_id, (field, file, line) in KNOWN_BAD_ANCHORS.items():
            with self.subTest(entry_id=entry_id):
                self.assertNotEqual(location(self.entries[entry_id][field]), (file, line))

    def test_review_csv_covers_exact_target_set(self) -> None:
        with (REPO_ROOT / "issue-6-fix-diff.csv").open(
            encoding="utf-8", newline=""
        ) as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), len(EXPECTED_NODES))
        self.assertEqual({row["entry_id"] for row in rows}, set(EXPECTED_NODES))
        self.assertTrue(all(row["status"] == "source_confirmed_verify_0" for row in rows))

    def test_all_changed_nodes_match_the_pinned_n8n_source(self) -> None:
        if not SOURCE_CACHE.exists():
            self.skipTest(f"n8n source cache not available: {SOURCE_CACHE}")

        source_files: dict[tuple[str, str], list[str]] = {}
        matched_nodes = 0
        for entry_id in EXPECTED_NODES:
            entry = self.entries[entry_id]
            for node in iter_nodes(entry):
                key = (entry["commit"], node["file"])
                if key not in source_files:
                    result = subprocess.run(
                        [
                            "git",
                            f"--git-dir={SOURCE_CACHE}",
                            "show",
                            f"{entry['commit']}:{node['file']}",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                    )
                    source_files[key] = result.stdout.splitlines()

                start, end = line_bounds(node["line"])
                actual = "\n".join(source_files[key][start - 1 : end])
                with self.subTest(entry_id=entry_id, file=node["file"], line=node["line"]):
                    self.assertEqual(actual, node["code"])
                matched_nodes += 1

        self.assertEqual(matched_nodes, 50)


if __name__ == "__main__":
    unittest.main()
