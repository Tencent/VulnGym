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
        self.assertIsNone(fix.parse_line_span(True))

    def test_low_information_needle_is_not_auto_fixable(self):
        self.assertTrue(fix.is_low_information_needle(fix.normalize_code_lines("}")))
        self.assertTrue(fix.is_low_information_needle(fix.normalize_code_lines(");")))
        self.assertFalse(fix.is_low_information_needle(fix.normalize_code_lines("return value;")))

    def test_desc_rewrite_updates_contextual_line_reference(self):
        desc, status = fix.maybe_update_desc(
            "example.ts \u7b2c 10 \u884c forwards the value",
            old_file="src/example.ts",
            old_line=10,
            new_file="src/example.ts",
            new_line=12,
        )

        self.assertEqual(status, "updated_by_text_rewrite")
        self.assertIn("\u7b2c 12 \u884c", desc)

    def test_markdown_count_table_renders_empty_counts(self):
        table = fix.markdown_count_table("Reasons", fix.Counter())

        self.assertIn("| none | 0 |", table)

    def test_full_dataset_scan_is_the_default(self):
        self.assertEqual(fix.parse_args([]).verify, "all")

    def test_integer_line_is_valid_multiline_start_anchor(self):
        class Workspace:
            def search_file(self, *_args, **_kwargs):
                return [fix.Match(file="src/example.py", start=10, end=11)]

            def search_repo(self, *_args, **_kwargs):
                raise AssertionError("repo search should not run for an exact start anchor")

        node = {
            "file": "src/example.py",
            "line": 10,
            "code": "value = source\nreturn value",
            "desc": "input propagation",
        }
        entry = {"entry_id": "entry-test", "verify": 0}
        diff_rows = []
        human_rows = []
        result = fix.fix_node(
            workspace=Workspace(),
            entry=entry,
            field_path="entry_point",
            node=node,
            diff_rows=diff_rows,
            human_rows=human_rows,
            args=fix.parse_args([]),
        )
        self.assertEqual(result, "ok")
        self.assertEqual(node["line"], 10)
        self.assertEqual(diff_rows, [])
        self.assertEqual(human_rows, [])

    def test_source_identity_rejects_non_github_and_invalid_commit(self):
        with self.assertRaises(fix.CheckoutError):
            fix.validate_source_identity("file:///tmp/repo", "a" * 40)
        with self.assertRaises(fix.CheckoutError):
            fix.validate_source_identity("https://github.com/owner/repo", "main")

    def test_committed_summary_mentions_verifier(self):
        summary = (SCRIPT.parents[1] / "reports" / "code_location_summary.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("scripts/verify_code_location_outputs.py", summary)
