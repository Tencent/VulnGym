import csv
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tools" / "fix_code_locations.py"
SPEC = importlib.util.spec_from_file_location("fix_code_locations", SCRIPT)
fixer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = fixer
SPEC.loader.exec_module(fixer)


class FakeSnapshot:
    def __init__(self, files, repository_matches=()):
        self.files = files
        self.repository_matches = tuple(repository_matches)

    def read_blob(self, commit, relative_path):
        del commit
        return self.files.get(relative_path)

    def search(self, commit, code):
        del commit, code
        return self.repository_matches


def git(cwd, *args):
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, encoding="utf-8", capture_output=True
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


class NormalizationTests(unittest.TestCase):
    def test_whitespace_tolerant_multiline_match(self):
        source = "before\n\tcall( one,\t two );\n\nafter\n"
        code = "\n  call( one,   two );\n\n"
        self.assertEqual(fixer.find_matches(source, code), [2])

    def test_internal_blank_lines_remain_significant(self):
        source = "one()\n\ntwo()\none()\ntwo()\n"
        self.assertEqual(fixer.find_matches(source, "one()\n\ntwo()"), [1])

    def test_annotator_chinese_comment_is_projected_after_exact_match_fails(self):
        source = "const value = input;\n"
        code = "const value = input; // 标注者补充的说明"
        self.assertEqual(fixer.find_matches(source, code), [1])

    def test_comment_markers_inside_strings_are_not_projected(self):
        code = 'const url = "https://example.com"; // 中文说明'
        self.assertEqual(
            fixer.projected_annotation_lines(code),
            ['const url = "https://example.com";'],
        )

    def test_parse_and_format_preserve_line_representation(self):
        self.assertEqual(fixer.parse_line(4), fixer.LineSpan(4, 4, False))
        self.assertEqual(fixer.parse_line("4-6"), fixer.LineSpan(4, 6, True))
        self.assertEqual(fixer.format_repaired_line(8, 3, 4), 8)
        self.assertEqual(fixer.format_repaired_line(8, 3, "4-6"), "8-10")

    def test_unsafe_repository_path_is_rejected(self):
        with self.assertRaises(fixer.RepairError):
            fixer.normalize_repository_path("../secret.py")


class LocateTests(unittest.TestCase):
    COMMIT = "a" * 40

    def test_exact_integer_is_a_start_anchor_for_multiline_code(self):
        snapshot = FakeSnapshot({"a.py": "one()\ntwo()\n"})
        node = {"file": "a.py", "line": 1, "code": "one()\ntwo()"}
        self.assertEqual(fixer.locate(snapshot, self.COMMIT, node).strategy, "exact")

    def test_bad_range_is_repaired_from_unique_nearby_match(self):
        snapshot = FakeSnapshot({"a.py": "x\none()\ntwo()\n"})
        node = {"file": "a.py", "line": "2-2", "code": "one()\ntwo()"}
        result = fixer.locate(snapshot, self.COMMIT, node)
        self.assertEqual(result.strategy, "nearby")
        self.assertEqual(result.candidate, fixer.Candidate("a.py", 2, 3))

    def test_unique_same_file_match(self):
        snapshot = FakeSnapshot({"a.py": "x\ny\nz\ntarget()\n"})
        node = {"file": "a.py", "line": 20, "code": "target()"}
        result = fixer.locate(snapshot, self.COMMIT, node)
        self.assertEqual((result.strategy, result.candidate.start), ("same_file", 4))

    def test_unique_repository_match_repairs_path(self):
        candidate = fixer.Candidate("new.py", 7, 7)
        snapshot = FakeSnapshot({"old.py": "nothing\n"}, (candidate,))
        node = {"file": "old.py", "line": 2, "code": "target()"}
        result = fixer.locate(snapshot, self.COMMIT, node)
        self.assertEqual((result.strategy, result.candidate), ("repository", candidate))

    def test_multiple_nearby_matches_are_never_guessed(self):
        snapshot = FakeSnapshot({"a.py": "x\ntarget()\ntarget()\n"})
        node = {"file": "a.py", "line": 5, "code": "target()"}
        result = fixer.locate(snapshot, self.COMMIT, node)
        self.assertIsNone(result.strategy)
        self.assertEqual(result.reason, "multiple matches within +/-5 lines")
        self.assertEqual(len(result.candidates), 2)

    def test_multiple_repository_matches_are_never_guessed(self):
        candidates = (
            fixer.Candidate("a.py", 1, 1),
            fixer.Candidate("b.py", 2, 2),
        )
        snapshot = FakeSnapshot({"old.py": "nothing\n"}, candidates)
        node = {"file": "old.py", "line": 1, "code": "target()"}
        result = fixer.locate(snapshot, self.COMMIT, node)
        self.assertEqual(result.reason, "multiple matches in repository")
        self.assertEqual(result.candidates, candidates)


class DescriptionTests(unittest.TestCase):
    def test_explicit_file_and_chinese_line_reference_are_updated(self):
        safe, desc, reason = fixer.synchronize_desc(
            "sink 位于 old.py 第 20 行。",
            "src/old.py",
            20,
            "lib/new.py",
            25,
        )
        self.assertTrue(safe, reason)
        self.assertEqual(desc, "sink 位于 new.py 第 25 行。")

    def test_range_dash_variants_are_updated(self):
        safe, desc, reason = fixer.synchronize_desc(
            "代码位于第 605–614 行。", "a.py", "605-614", "a.py", "606-615"
        )
        self.assertTrue(safe, reason)
        self.assertEqual(desc, "代码位于第 606-615 行。")

    def test_unrelated_numbers_are_not_replaced(self):
        safe, desc, reason = fixer.synchronize_desc(
            "CVE-2026-25020 的问题位于第 20 行。", "a.py", 20, "a.py", 25
        )
        self.assertTrue(safe, reason)
        self.assertEqual(desc, "CVE-2026-25020 的问题位于第 25 行。")

    def test_ambiguous_location_reference_requires_review(self):
        safe, desc, reason = fixer.synchronize_desc(
            "问题大约位于位置 20 附近。", "a.py", 20, "a.py", 25
        )
        self.assertFalse(safe)
        self.assertIn("ambiguous old line", reason)
        self.assertEqual(desc, "问题大约位于位置 20 附近。")


class GitSnapshotTests(unittest.TestCase):
    def test_pinned_commit_blob_and_repository_search(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            git(source, "init")
            git(source, "config", "user.name", "Test")
            git(source, "config", "user.email", "test@example.com")
            (source / "code.py").write_text("old_value()\n", encoding="utf-8")
            (source / "other.py").write_text("other_value()\n", encoding="utf-8")
            git(source, "add", "code.py", "other.py")
            git(source, "commit", "-m", "old")
            old_commit = git(source, "rev-parse", "HEAD")
            (source / "code.py").write_text("new_value()\n", encoding="utf-8")
            git(source, "commit", "-am", "new")

            fake_url = "https://github.com/acme/pinned-example"
            cache_root = root / "cache"
            bare = fixer.cache_path_for_repo(fake_url, cache_root)
            bare.parent.mkdir(parents=True)
            git(root, "clone", "--bare", str(source), str(bare))
            git(bare, "remote", "set-url", "origin", fake_url)

            snapshot = fixer.RepoCache(fake_url, cache_root, offline=True, timeout=30)
            snapshot.ensure_commit(old_commit)
            self.assertEqual(snapshot.read_blob(old_commit, "code.py"), "old_value()\n")
            archive = snapshot._archive_path(old_commit)
            archive.parent.mkdir(parents=True)
            with tarfile.open(archive, "w:gz") as bundle:
                for relative, content in {
                    "code.py": b"old_value()\n",
                    "other.py": b"other_value()\n",
                }.items():
                    info = tarfile.TarInfo(f"pinned-example-{old_commit}/{relative}")
                    info.size = len(content)
                    bundle.addfile(info, io.BytesIO(content))
            self.assertEqual(
                snapshot.search(old_commit, "old_value()"),
                (fixer.Candidate("code.py", 1, 1),),
            )
            batch = snapshot.search_many(old_commit, ["old_value()", "other_value()"])
            self.assertEqual(
                batch[("other_value()",)],
                (fixer.Candidate("other.py", 1, 1),),
            )


class OutputAndSchemaTests(unittest.TestCase):
    def test_current_dataset_satisfies_entry_invariants(self):
        entries = fixer.load_jsonl(Path(__file__).parents[1] / "data" / "entries.jsonl")
        fixer.validate_entries(entries)
        self.assertEqual(len(entries), 408)

    def test_csv_round_trips_multiline_code_and_chinese(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review.csv"
            row = {field: "" for field in fixer.HUMAN_FIELDS}
            row.update({"entry_id": "entry-00001", "code": "一行\n二行"})
            fixer.atomic_write_csv(output, fixer.HUMAN_FIELDS, [row])
            with output.open(encoding="utf-8-sig", newline="") as handle:
                loaded = list(csv.DictReader(handle))
            self.assertEqual(loaded[0]["code"], "一行\n二行")

    def test_jsonl_is_sorted_and_round_trips_unicode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.jsonl"
            fixer.atomic_write_jsonl(output, [{"z": "中文", "a": 1}])
            self.assertEqual(output.read_text(encoding="utf-8"), '{"a":1,"z":"中文"}\n')
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"a": 1, "z": "中文"})


if __name__ == "__main__":
    unittest.main()
