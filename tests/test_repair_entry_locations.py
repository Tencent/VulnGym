from __future__ import annotations

import argparse
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.repair_entry_locations import (
    GitSourceCache,
    find_matches_in_lines,
    is_low_information,
    normalize_code_lines,
    normalize_line,
    normalize_path,
    parse_line_span,
    resolve_node,
    sha256_file,
    synchronize_desc,
)


class MemorySource:
    def __init__(self, files: dict[str, str]) -> None:
        self.files = {
            normalize_path(path): [normalize_line(line) for line in text.splitlines()]
            for path, text in files.items()
        }

    def search_file(
        self,
        commit: str,
        file: str,
        needle: tuple[str, ...],
        *,
        start_min: int | None = None,
        start_max: int | None = None,
    ):
        path = normalize_path(file)
        lines = self.files.get(path)
        if lines is None:
            return []
        return find_matches_in_lines(
            file=path,
            normalized_lines=lines,
            needle=needle,
            start_min=start_min,
            start_max=start_max,
        )

    def search_repo(self, commit: str, needle: tuple[str, ...]):
        result = []
        for path, lines in sorted(self.files.items()):
            result.extend(
                find_matches_in_lines(file=path, normalized_lines=lines, needle=needle)
            )
        return result


def node(file: str, line, code: str, desc: str = ""):
    return {"file": file, "line": line, "code": code, "desc": desc}


class NormalizationTests(unittest.TestCase):
    def test_code_normalization_supports_multiline_and_whitespace(self):
        self.assertEqual(
            normalize_code_lines("\n\talpha(  x )\n  beta\t=  2  \n"),
            ("alpha( x )", "beta = 2"),
        )

    def test_line_span_parsing(self):
        self.assertEqual((parse_line_span(7).start, parse_line_span(7).end), (7, 7))
        self.assertEqual(
            (parse_line_span("7-9").start, parse_line_span("7-9").end), (7, 9)
        )
        self.assertIsNone(parse_line_span(0))
        self.assertIsNone(parse_line_span("9-7"))
        self.assertIsNone(parse_line_span(True))

    def test_low_information_detection(self):
        self.assertTrue(is_low_information(("}",)))
        self.assertTrue(is_low_information(("x",)))
        self.assertFalse(is_low_information(("return value;",)))

    def test_file_hash_is_stable_across_newline_styles(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            lf_path = root / "lf.txt"
            crlf_path = root / "crlf.txt"
            lf_path.write_bytes(b"alpha\nbeta\n")
            crlf_path.write_bytes(b"alpha\r\nbeta\r\n")
            self.assertEqual(sha256_file(lf_path), sha256_file(crlf_path))


class ResolutionTests(unittest.TestCase):
    def test_exact_current_low_information_is_accepted(self):
        source = MemorySource({"a.ts": "start\n}\nend"})
        result = resolve_node(source, commit="x", node=node("a.ts", 2, "}"), nearby_lines=5)
        self.assertEqual(result.status, "ok")

    def test_mismatching_low_information_goes_to_human(self):
        source = MemorySource({"a.ts": "}\nother\n}"})
        result = resolve_node(source, commit="x", node=node("a.ts", 2, "}"), nearby_lines=5)
        self.assertEqual((result.status, result.reason), ("human", "low_information_code"))

    def test_current_start_repairs_multiline_span(self):
        source = MemorySource({"a.py": "one\ntwo\nthree"})
        result = resolve_node(
            source,
            commit="x",
            node=node("a.py", 1, "one\ntwo"),
            nearby_lines=5,
        )
        self.assertEqual(result.status, "fixed")
        self.assertEqual(result.strategy, "current_start_span_repair")
        self.assertEqual(result.match.line_value, "1-2")

    def test_nearby_unique_ignores_tabs_and_space_runs(self):
        source = MemorySource({"a.py": "zero\nalpha\n\tcall(  value )\nomega"})
        result = resolve_node(
            source,
            commit="x",
            node=node("a.py", 1, "  call( value )"),
            nearby_lines=5,
        )
        self.assertEqual(result.status, "fixed")
        self.assertEqual(result.strategy, "nearby_plus_minus_5")
        self.assertEqual(result.match.line_value, 3)

    def test_same_file_unique_after_nearby_miss(self):
        source = MemorySource({"a.py": "wrong\n" + "filler\n" * 8 + "unique_call()"})
        result = resolve_node(
            source,
            commit="x",
            node=node("a.py", 1, "unique_call()"),
            nearby_lines=5,
        )
        self.assertEqual((result.status, result.strategy), ("fixed", "same_file_unique"))
        self.assertEqual(result.match.line_value, 10)

    def test_repository_unique_repairs_file_and_line(self):
        source = MemorySource({"old.py": "wrong", "pkg/new.py": "header\nunique_call()"})
        result = resolve_node(
            source,
            commit="x",
            node=node("old.py", 1, "unique_call()"),
            nearby_lines=5,
        )
        self.assertEqual((result.status, result.strategy), ("fixed", "repository_unique"))
        self.assertEqual((result.match.file, result.match.line_value), ("pkg/new.py", 2))

    def test_multiple_nearby_matches_are_not_forced(self):
        source = MemorySource({"a.py": "unique_call()\nwrong\nunique_call()"})
        result = resolve_node(
            source,
            commit="x",
            node=node("a.py", 2, "unique_call()"),
            nearby_lines=5,
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(result.reason, "multiple_matches_in_nearby")

    def test_no_match_goes_to_human(self):
        source = MemorySource({"a.py": "present()"})
        result = resolve_node(
            source,
            commit="x",
            node=node("a.py", 1, "missing_call()"),
            nearby_lines=5,
        )
        self.assertEqual((result.status, result.reason), ("human", "no_match"))


class DescriptionTests(unittest.TestCase):
    def test_desc_location_references_are_synchronized(self):
        desc, status = synchronize_desc(
            "old/file.py 第 12 行 calls sink; file.py:12 and line 12.",
            old_file="old/file.py",
            old_line=12,
            new_file="new/sink.py",
            new_line="20-21",
        )
        self.assertEqual(status, "updated_location_references")
        self.assertIn("new/sink.py 第 20-21 行", desc)
        self.assertIn("sink.py:20-21", desc)
        self.assertIn("line 20-21", desc)

    def test_desc_without_location_is_explicitly_checked(self):
        desc, status = synchronize_desc(
            "This node invokes the final sink.",
            old_file="a.py",
            old_line=1,
            new_file="a.py",
            new_line=2,
        )
        self.assertEqual(desc, "This node invokes the final sink.")
        self.assertEqual(status, "checked_no_location_reference")


class GitSourceCacheTests(unittest.TestCase):
    def test_bare_cache_reads_and_searches_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_repo = root / "source"
            source_repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=source_repo, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.com"],
                cwd=source_repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"], cwd=source_repo, check=True
            )
            (source_repo / "a.py").write_text("alpha\ncall(  value )\n", encoding="utf-8")
            (source_repo / "b.py").write_text("other\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.py", "b.py"], cwd=source_repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=source_repo, check=True)
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=source_repo, text=True
            ).strip()
            args = argparse.Namespace(
                cache_dir=root / "cache",
                offline=False,
                git_protocol="https",
                git_timeout=30,
                max_file_bytes=1024 * 1024,
                max_repo_matches=10,
            )
            cache = GitSourceCache(str(source_repo), args)
            cache.prepare({commit})
            matches = cache.search_repo(commit, normalize_code_lines("call( value )"))
            self.assertEqual([(item.file, item.start, item.end) for item in matches], [("a.py", 2, 2)])


if __name__ == "__main__":
    unittest.main()
