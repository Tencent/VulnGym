# -*- coding: utf-8 -*-
"""Unit tests for tools/fix_locations/fix_code_locations.py (GREEN local only)."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "fix_locations" / "fix_code_locations.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("fix_code_locations", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


M = _load_mod()


class TestNormalizeAndLine(unittest.TestCase):
    def test_normalize_collapses_whitespace(self):
        a = "foo(\n\tbar  )"
        b = "foo(\n bar )"
        self.assertEqual(M.normalize_code(a), M.normalize_code(b))

    def test_normalize_strips_edge_blank_lines(self):
        self.assertEqual(M.normalize_code("\n  x  \n\n"), "x")

    def test_line_span_int_and_range(self):
        self.assertEqual(M.LineSpan.parse(7).as_json(), 7)
        self.assertEqual(M.LineSpan.parse("7-9").as_json(), "7-9")
        with self.assertRaises(ValueError):
            M.LineSpan.parse(0)
        with self.assertRaises(ValueError):
            M.LineSpan.parse("9-7")


class TestDegenerate(unittest.TestCase):
    def test_brace_is_degenerate(self):
        self.assertTrue(M.is_degenerate_code("}"))
        self.assertTrue(M.is_degenerate_code("});"))
        self.assertTrue(M.is_degenerate_code(""))

    def test_real_code_not_degenerate(self):
        self.assertFalse(M.is_degenerate_code("return sanitize(input);"))
        self.assertFalse(M.is_degenerate_code("tempDiv.innerHTML = htmlContent;"))


class TestFindUnique(unittest.TestCase):
    def setUp(self):
        self.lines = [
            "alpha",
            "foo()",
            "bar()",
            "foo()",
            "baz()",
        ]

    def test_unique_in_neighborhood(self):
        hit = M.find_unique_in_lines(self.lines, "bar()", lo=1, hi=5)
        self.assertEqual(hit, M.LineSpan(3, 3))

    def test_ambiguous_returns_none(self):
        self.assertIsNone(M.find_unique_in_lines(self.lines, "foo()"))

    def test_multiline_unique(self):
        lines = ["a", "x = 1", "y = 2", "z = 3", "b"]
        hit = M.find_unique_in_lines(lines, "x = 1\ny = 2")
        self.assertEqual(hit, M.LineSpan(2, 3))


class TestRepairNode(unittest.TestCase):
    def _repo(self, files: dict[str, str]) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        # minimal git repo for list_repo_files if needed
        (root / ".git").mkdir()
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return root

    def test_already_matches(self):
        repo = self._repo({"a.py": "print(1)\nprint(2)\n"})
        node = {"file": "a.py", "line": 2, "code": "print(2)"}
        r = M.repair_node(repo, node, allow_repo_wide=False)
        self.assertEqual(r.status, "ok")

    def test_neighborhood_fix(self):
        repo = self._repo({"a.py": "print(1)\nprint(2)\nprint(3)\n"})
        node = {"file": "a.py", "line": 1, "code": "print(3)"}
        r = M.repair_node(repo, node, allow_repo_wide=False)
        self.assertEqual(r.status, "fixed")
        self.assertEqual(r.strategy, "neighborhood_pm5")
        self.assertEqual(r.new_line, 3)

    def test_degenerate_even_if_matches(self):
        repo = self._repo({"a.py": "x = 1\n}\n"})
        node = {"file": "a.py", "line": 2, "code": "}"}
        r = M.repair_node(repo, node, allow_repo_wide=False)
        self.assertEqual(r.status, "needs_human")
        self.assertEqual(r.reason, "degenerate_snippet")

    def test_ambiguous_needs_human(self):
        repo = self._repo({"a.py": "foo()\nbar()\nfoo()\n"})
        node = {"file": "a.py", "line": 2, "code": "foo()"}
        r = M.repair_node(repo, node, allow_repo_wide=False)
        self.assertEqual(r.status, "needs_human")

    def test_range_completion_counts_as_fix(self):
        """Single-line annotation for multi-line snippet → expand span."""
        repo = self._repo({"a.py": "a\nx = 1\ny = 2\nb\n"})
        node = {"file": "a.py", "line": 2, "code": "x = 1\ny = 2"}
        r = M.repair_node(repo, node, allow_repo_wide=False)
        self.assertEqual(r.status, "fixed")
        self.assertEqual(r.new_line, "2-3")

    def _patch_list_repo_files(self, files: list[Path]):
        real = M.list_repo_files

        def fake_list(path: Path):
            return [path / rel for rel in files]

        M.list_repo_files = fake_list  # type: ignore[assignment]
        self.addCleanup(lambda: setattr(M, "list_repo_files", real))

    def test_repo_wide_unique(self):
        repo = self._repo(
            {
                "wrong.py": "nope\n",
                "right.py": "needle_unique_zzz()\n",
            }
        )
        self._patch_list_repo_files([Path("wrong.py"), Path("right.py")])
        node = {"file": "missing.py", "line": 1, "code": "needle_unique_zzz()"}
        r = M.repair_node(repo, node, allow_repo_wide=True)
        self.assertEqual(r.status, "fixed")
        self.assertEqual(r.strategy, "repo_wide_unique")
        self.assertEqual(r.new_file, "right.py")

    def test_repo_wide_ambiguous(self):
        repo = self._repo(
            {
                "a.py": "shared_needle_abc()\n",
                "b.py": "shared_needle_abc()\n",
            }
        )
        self._patch_list_repo_files([Path("a.py"), Path("b.py")])
        node = {"file": "missing.py", "line": 1, "code": "shared_needle_abc()"}
        r = M.repair_node(repo, node, allow_repo_wide=True)
        self.assertEqual(r.status, "needs_human")
        self.assertEqual(r.reason, "repo_wide_ambiguous")

    def test_repo_wide_no_match(self):
        repo = self._repo({"a.py": "other()\n"})
        self._patch_list_repo_files([Path("a.py")])
        node = {"file": "missing.py", "line": 1, "code": "totally_absent_xyz()"}
        r = M.repair_node(repo, node, allow_repo_wide=True)
        self.assertEqual(r.status, "needs_human")
        self.assertEqual(r.reason, "repo_wide_no_match")


class TestSchemaSmokeHelpers(unittest.TestCase):
    def test_priority_ids_present(self):
        self.assertEqual(len(M.PRIORITY_IDS), 4)
        self.assertIn("entry-00103", M.PRIORITY_IDS)


if __name__ == "__main__":
    unittest.main()
