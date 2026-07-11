from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from code_location_repair import (  # noqa: E402
    Match,
    NodeTask,
    apply_results,
    find_matches,
    match_has_annotated_location,
    normalize_code,
    normalized_source,
    repair_commit_tasks,
    repaired_line,
    update_desc,
)


def make_node(file: str = "src/a.py", line: int | str = 10, code: str = "call()") -> dict:
    return {"file": file, "line": line, "code": code, "desc": "a.py 第 10 行调用"}


def make_entry(node: dict) -> dict:
    return {
        "commit": "a" * 40,
        "critical_operation": copy.deepcopy(node),
        "entry_id": "entry-00001",
        "entry_point": copy.deepcopy(node),
        "repo_url": "https://github.com/example/project",
        "trace": [],
        "verify": 0,
    }


def make_task(node: dict, task_id: int = 0) -> NodeTask:
    return NodeTask(
        task_id=task_id,
        entry_index=0,
        entry_id="entry-00001",
        field_path="entry_point",
        node_key="entry_point",
        trace_index=None,
        repo_url="https://github.com/example/project",
        commit="a" * 40,
        node=node,
    )


class FakeRepository:
    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def read_file(self, commit: str, file: str) -> str | None:
        return self.files.get(file)

    def search_repository(self, commit: str, snippets):
        result = {}
        for snippet in set(snippets):
            matches = []
            for file, text in self.files.items():
                matches.extend(find_matches(normalized_source(text), snippet, file=file))
            result[snippet] = matches[:5]
        return result


class NormalizationTests(unittest.TestCase):
    def test_ignores_outer_whitespace_and_tab_space_differences(self) -> None:
        snippet = normalize_code("\n\tif value:\n\t\tcall(value)\n")
        source = normalized_source("  if   value:\n        call(value)\n")
        self.assertEqual(len(find_matches(source, snippet, file="a.py")), 1)

    def test_supports_multiline_matches(self) -> None:
        matches = find_matches(
            normalized_source("before\nfirst()\nsecond()\nafter\n"),
            normalize_code("first()\nsecond()"),
            file="a.py",
        )
        self.assertEqual(matches, [Match("a.py", 2, 3)])


class StrategyTests(unittest.TestCase):
    def test_exact_location_is_unchanged(self) -> None:
        task = make_task(make_node(line=2))
        results = repair_commit_tasks(
            FakeRepository({"src/a.py": "before\ncall()\n"}), task.commit, [task], 5
        )
        self.assertEqual(results[0].status, "matched")
        self.assertEqual(results[0].strategy, "exact")

    def test_unique_nearby_location_is_fixed(self) -> None:
        task = make_task(make_node(line=5))
        results = repair_commit_tasks(
            FakeRepository({"src/a.py": "before\ncall()\n"}), task.commit, [task], 5
        )
        self.assertEqual(results[0].strategy, "nearby_unique")
        self.assertEqual(results[0].match, Match("src/a.py", 2, 2))

    def test_unique_file_location_is_fixed(self) -> None:
        task = make_task(make_node(line=50))
        results = repair_commit_tasks(
            FakeRepository({"src/a.py": "before\ncall()\n"}), task.commit, [task], 5
        )
        self.assertEqual(results[0].strategy, "file_unique")

    def test_unique_repository_location_updates_file(self) -> None:
        task = make_task(make_node(file="missing.py", line=1))
        results = repair_commit_tasks(
            FakeRepository({"src/actual.py": "call()\n"}), task.commit, [task], 5
        )
        self.assertEqual(results[0].strategy, "repository_unique")
        self.assertEqual(results[0].match, Match("src/actual.py", 1, 1))

    def test_multiple_matches_require_human_review(self) -> None:
        task = make_task(make_node(line=10))
        repository = FakeRepository({"src/a.py": "call()\nother\ncall()\n"})
        results = repair_commit_tasks(repository, task.commit, [task], 20)
        self.assertEqual(results[0].status, "human")
        self.assertEqual(results[0].reason, "multiple_nearby_matches")

    def test_missing_code_requires_human_review(self) -> None:
        task = make_task(make_node(code="absent()"))
        results = repair_commit_tasks(
            FakeRepository({"src/a.py": "call()\n"}), task.commit, [task], 5
        )
        self.assertEqual(results[0].status, "human")
        self.assertEqual(results[0].reason, "code_not_found_in_repository")


class OutputTests(unittest.TestCase):
    def test_preserves_original_line_representation(self) -> None:
        match = Match("a.py", 20, 22)
        self.assertEqual(repaired_line(10, match), 20)
        self.assertEqual(repaired_line("10-12", match), "20-22")

    def test_range_requires_both_boundaries_to_match(self) -> None:
        match = Match("a.py", 10, 12)
        self.assertTrue(match_has_annotated_location(10, match))
        self.assertTrue(match_has_annotated_location("10-12", match))
        self.assertFalse(match_has_annotated_location("10-13", match))

    def test_updates_structured_desc_locations(self) -> None:
        desc = "a.py 第 10 行 and line 10 and L10"
        self.assertEqual(
            update_desc(desc, "src/a.py", 10, "lib/b.py", 20),
            "b.py 第 20 行 and line 20 and L20",
        )

    def test_apply_results_updates_data_and_diff(self) -> None:
        node = make_node()
        entry = make_entry(node)
        task = make_task(entry["entry_point"])
        from code_location_repair import TaskResult

        result = TaskResult(
            task=task,
            status="fixed",
            strategy="repository_unique",
            match=Match("src/b.py", 20, 20),
        )
        output, fixes, human = apply_results([entry], [result])
        self.assertEqual(output[0]["entry_point"]["file"], "src/b.py")
        self.assertEqual(output[0]["entry_point"]["line"], 20)
        self.assertEqual(len(fixes), 1)
        self.assertEqual(human, [])


if __name__ == "__main__":
    unittest.main()
