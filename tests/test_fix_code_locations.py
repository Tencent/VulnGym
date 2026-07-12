import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("fixer", Path(__file__).parents[1] / "tools" / "fix_code_locations.py")
fixer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = fixer
SPEC.loader.exec_module(fixer)


class FakeSnapshot:
    def __init__(self, files):
        self._files = files

    def read(self, relative):
        return self._files.get(relative)

    def files(self):
        return iter(self._files.items())


class LocationFixerTests(unittest.TestCase):
    def test_snapshot_cache_paths_are_absolute(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = fixer.RepositorySnapshot("https://github.com/acme/example", "a" * 40, Path(directory))
            self.assertTrue(snapshot.root.is_absolute())

    def test_whitespace_tolerant_multiline_match(self):
        text = "before\n  call( one,\t two );\nafter\n"
        self.assertEqual(fixer.find_matches(text, "call( one,  two );"), [2])

    def test_source_leading_blank_lines_do_not_shift_result(self):
        self.assertEqual(fixer.find_matches("\n\ntarget()\n", "target()"), [3])

    def test_internal_blank_lines_are_supported(self):
        self.assertEqual(fixer.find_matches("one()\n\ntwo()\n", "one()\n\ntwo()"), [1])

    def test_description_line_range_is_synchronized(self):
        desc = "位于第 605–614 行，范围 605-614。"
        self.assertEqual(
            fixer.update_desc_location(desc, "605-614", "606-614"),
            "位于第 606-614 行，范围 606-614。",
        )

    def test_nearby_unique_match_repairs_range(self):
        snapshot = FakeSnapshot({"a.py": "x\ny\nfirst()\n second()\n"})
        node = {"file": "a.py", "line": "1-2", "code": "first()\nsecond()"}
        result = fixer.locate(snapshot, node)
        self.assertEqual((result.strategy, result.line), ("nearby", "3-4"))

    def test_unique_repository_match_repairs_file(self):
        snapshot = FakeSnapshot({"old.py": "nothing\n", "new.py": "target()\n"})
        node = {"file": "old.py", "line": 9, "code": "target()"}
        result = fixer.locate(snapshot, node)
        self.assertEqual((result.strategy, result.file, result.line), ("repository", "new.py", 1))

    def test_ambiguous_match_is_not_repaired(self):
        snapshot = FakeSnapshot({"a.py": "same()\nsame()\n"})
        node = {"file": "a.py", "line": 20, "code": "same()"}
        result = fixer.locate(snapshot, node)
        self.assertIsNone(result.strategy)
        self.assertEqual(result.reason, "multiple matches in original file")
        self.assertEqual(len(result.candidates), 2)

    def test_exact_range_requires_matching_span(self):
        snapshot = FakeSnapshot({"a.py": "one()\ntwo()\n"})
        node = {"file": "a.py", "line": "1-1", "code": "one()\ntwo()"}
        result = fixer.locate(snapshot, node)
        self.assertEqual((result.strategy, result.line), ("nearby", "1-2"))


if __name__ == "__main__":
    unittest.main()
