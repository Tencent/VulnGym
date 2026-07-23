# -*- coding: utf-8 -*-
"""
Unit tests for fix_entries.py
Coverage: normalize_code, search_code_in_lines, _parse_line, build_raw_url,
          is_degenerate_snippet, sync_desc
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fix_entries import (
    normalize_code,
    search_code_in_lines,
    _parse_line,
    build_raw_url,
    is_degenerate_snippet,
    sync_desc,
)


class TestNormalizeCode(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(normalize_code("hello world"), "hello world")

    def test_tabs_to_spaces(self):
        # normalize_code replaces tabs AND strips each line
        self.assertEqual(normalize_code("\t\treturn 1"), "return 1")

    def test_strips_leading_trailing_whitespace(self):
        # normalize strips each line and compresses empty lines
        result = normalize_code("\n  hello  \n\n  world  \n")
        self.assertIn("hello", result)
        self.assertIn("world", result)

    def test_multiline_code(self):
        code = "def foo():\n    return 1\n\n"
        result = normalize_code(code)
        self.assertEqual(result, "def foo():\nreturn 1")

    def test_empty_string(self):
        self.assertEqual(normalize_code(""), "")

    def test_only_whitespace(self):
        self.assertEqual(normalize_code("   \n \t \n  "), "")


class TestSearchCodeInLines(unittest.TestCase):
    def test_exact_match(self):
        lines = ["line0", "line1", "line2", "line3", "line4"]
        self.assertEqual(search_code_in_lines(lines, "line2"), [3])

    def test_not_found(self):
        lines = ["a", "b", "c"]
        self.assertEqual(search_code_in_lines(lines, "missing"), [])

    def test_multiline_match(self):
        lines = ["def foo():\n", "return 1\n", "def bar():\n"]
        result = search_code_in_lines(lines, "def foo():\nreturn 1")
        self.assertEqual(result, [1])


class TestParseLine(unittest.TestCase):
    def test_int(self):
        self.assertEqual(_parse_line(42), (42, 42))

    def test_range(self):
        self.assertEqual(_parse_line("20-25"), (20, 25))

    def test_single_line(self):
        self.assertEqual(_parse_line("7"), (7, 7))

    def test_invalid(self):
        self.assertIsNone(_parse_line("abc")[0])
        self.assertIsNone(_parse_line("")[0])


class TestBuildRawUrl(unittest.TestCase):
    def test_github_blob(self):
        raw = build_raw_url(
            "https://github.com/user/repo", "abc123", "path/to/file.py"
        )
        self.assertIn("raw.githubusercontent.com", raw)
        self.assertIn("abc123", raw)
        self.assertIn("path/to/file.py", raw)


class TestIsDegenerateSnippet(unittest.TestCase):
    def test_braces(self):
        self.assertTrue(is_degenerate_snippet("}"))
        self.assertTrue(is_degenerate_snippet(")"))
        self.assertTrue(is_degenerate_snippet("];"))

    def test_meaningful_code(self):
        self.assertFalse(is_degenerate_snippet("return 1"))
        self.assertFalse(is_degenerate_snippet("const x = 1;"))
        self.assertFalse(is_degenerate_snippet("import os"))

    def test_empty(self):
        self.assertTrue(is_degenerate_snippet(""))
        self.assertTrue(is_degenerate_snippet("  "))


class TestSyncDesc(unittest.TestCase):
    def test_no_line_ref(self):
        desc = "plain description with no numbers."
        self.assertEqual(
            sync_desc(desc, "/a.py", "/a.py", 100, 100, 200, 200), desc
        )

    def test_update_single_line(self):
        desc = "bug at line 100."
        result = sync_desc(desc, "/a.py", "/a.py", 100, 100, 200, 200)
        self.assertIn("200", result)

    def test_file_changed_no_sync(self):
        desc = "bug at line 100."
        result = sync_desc(desc, "/a.py", "/b.py", 100, 100, 200, 200)
        self.assertEqual(result, desc)

    def test_line_range_in_desc(self):
        desc = "lines 100-105 of the method."
        result = sync_desc(desc, "/a.py", "/a.py", 100, 105, 200, 205)
        self.assertIn("200", result)
        self.assertIn("205", result)


if __name__ == "__main__":
    unittest.main()
