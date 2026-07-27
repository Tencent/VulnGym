import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent / "fix_entry_locations.py"
SPEC = importlib.util.spec_from_file_location("fix_entry_locations", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeSource:
    def __init__(self, files):
        self.files = files

    def read_file(self, repo_url, commit, file_path):
        if file_path not in self.files:
            raise MODULE.SourceError("missing")
        return self.files[file_path]

    def grep_files(self, repo_url, commit, token):
        return [path for path, text in self.files.items() if token in text]


class LocationRepairTests(unittest.TestCase):
    def test_multiline_whitespace_tolerance(self):
        text = "before\n\tif (ready) {\n        run();\n    }\nafter\n"
        code = "  if (ready) {\n\t run();\n}"
        self.assertEqual(MODULE.find_occurrences(text, code), [(2, 4)])

    def test_unique_nearby_match_repairs_line_and_desc(self):
        node = {
            "file": "src/a.py",
            "line": 10,
            "code": "target(value)",
            "desc": "src/a.py 第 10 行执行目标操作。",
        }
        source = FakeSource({"src/a.py": "\n" * 11 + "target(value)\n"})
        diff, human = MODULE.repair_node(
            entry_id="entry-00001",
            field_path="entry_point",
            node=node,
            repo_url="https://github.com/example/repo",
            commit="a" * 40,
            source=source,
            near_lines=5,
            max_candidate_files=500,
        )
        self.assertIsNone(human)
        self.assertEqual(node["line"], 12)
        self.assertEqual(diff["strategy"], "nearby_unique")
        self.assertIn("第 12 行", node["desc"])

    def test_multiple_matches_go_to_human_review(self):
        node = {
            "file": "src/a.py",
            "line": 5,
            "code": "target(value)",
            "desc": "ambiguous",
        }
        source = FakeSource(
            {
                "src/a.py": "target(value)\nother\ntarget(value)\n",
                "src/b.py": "target(value)\n",
            }
        )
        diff, human = MODULE.repair_node(
            entry_id="entry-00001",
            field_path="critical_operation",
            node=node,
            repo_url="https://github.com/example/repo",
            commit="a" * 40,
            source=source,
            near_lines=5,
            max_candidate_files=500,
        )
        self.assertIsNone(diff)
        self.assertEqual(human["reason"], "multiple_repository_matches")
        self.assertEqual(human["match_count"], 3)
        self.assertEqual(node["line"], 5)

    def test_desc_updates_unicode_range_separator(self):
        desc = "helper.ts 第 605–614 行处理输入。"
        updated = MODULE.update_desc_location(
            desc,
            "src/helper.ts",
            "605-614",
            "src/helper.ts",
            "606-614",
        )
        self.assertEqual(updated, "helper.ts 第 606-614 行处理输入。")

    def test_missing_code_goes_to_human_review(self):
        node = {"file": "src/a.py", "line": 2, "code": "not_here()", "desc": ""}
        source = FakeSource({"src/a.py": "present()\n"})
        diff, human = MODULE.repair_node(
            entry_id="entry-00001",
            field_path="trace[0]",
            node=node,
            repo_url="https://github.com/example/repo",
            commit="a" * 40,
            source=source,
            near_lines=5,
            max_candidate_files=500,
        )
        self.assertIsNone(diff)
        self.assertEqual(human["reason"], "code_not_found")

    def test_repository_unique_match_repairs_file_and_line(self):
        node = {
            "file": "src/old.py",
            "line": 20,
            "code": "unique_target(value)",
            "desc": "src/old.py 第 20 行执行目标操作。",
        }
        source = FakeSource({"src/new.py": "before\nunique_target(value)\nafter\n"})
        diff, human = MODULE.repair_node(
            entry_id="entry-00001",
            field_path="entry_point",
            node=node,
            repo_url="https://github.com/example/repo",
            commit="a" * 40,
            source=source,
            near_lines=5,
            max_candidate_files=500,
        )
        self.assertIsNone(human)
        self.assertEqual(diff["strategy"], "repo_unique")
        self.assertEqual(node["file"], "src/new.py")
        self.assertEqual(node["line"], 2)
        self.assertIn("src/new.py 第 2 行", node["desc"])


if __name__ == "__main__":
    unittest.main()
