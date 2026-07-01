import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fix_code_locations.py"
spec = importlib.util.spec_from_file_location("fix_code_locations", SCRIPT)
fix = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = fix
spec.loader.exec_module(fix)


class CodeLocationFixTests(unittest.TestCase):
    def test_normalize_code_lines_ignores_outer_blank_and_space_runs(self):
        code = "\n\tfoo(  bar,\t baz  );\n\n"
        self.assertEqual(fix.normalize_code_lines(code), ("foo( bar, baz );",))

    def test_find_matches_in_lines_supports_multiline_snippets(self):
        lines = [
            "before",
            "\tconst value = input;",
            "return   value;",
            "after",
        ]
        needle = fix.normalize_code_lines("const value = input;\nreturn value;")

        matches = fix.find_matches_in_lines(file_path="src/example.ts", lines=lines, needle=needle)

        self.assertEqual(matches, [fix.Match(file="src/example.ts", start=2, end=3)])
        self.assertEqual(matches[0].line_value, "2-3")

    def test_unique_or_reason_accepts_single_match_and_rejects_ambiguity(self):
        one = [fix.Match(file="a.py", start=10, end=10)]
        many = [
            fix.Match(file="a.py", start=10, end=10),
            fix.Match(file="b.py", start=20, end=20),
        ]

        self.assertEqual(fix.unique_or_reason(one, "repo"), (one[0], None))
        match, reason = fix.unique_or_reason(many, "repo")
        self.assertIsNone(match)
        self.assertEqual(reason, "multiple_matches_in_repo:2")

    def test_parse_line_span_accepts_int_and_range_only(self):
        self.assertEqual(fix.parse_line_span(7), fix.LineSpan(7, 7))
        self.assertEqual(fix.parse_line_span("7-9"), fix.LineSpan(7, 9))
        self.assertIsNone(fix.parse_line_span(0))
        self.assertIsNone(fix.parse_line_span("9-7"))

    def test_desc_rewrite_updates_contextual_line_reference(self):
        desc, status = fix.maybe_update_desc(
            "example.ts 第 10 行 forwards the value",
            old_file="src/example.ts",
            old_line=10,
            new_file="src/example.ts",
            new_line=12,
        )

        self.assertEqual(status, "updated_by_text_rewrite")
        self.assertIn("第 12 行", desc)
