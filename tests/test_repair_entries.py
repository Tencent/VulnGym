"""Tests for scripts/repair_entries.py.

Run with:
    cd <repo-root> && python -m pytest tests/test_repair_entries.py -v

Integration tests build a throwaway git repository under tmpdir; unit tests
operate on in-memory data only.
"""
from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import repair_entries as re_mod  # noqa: E402


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #


class TestNormalizeCodeBlock:
    def test_crlf_normalized(self):
        assert re_mod.normalize_code_block("a\r\nb") == ["a", "b"]

    def test_cr_normalized(self):
        assert re_mod.normalize_code_block("a\rb") == ["a", "b"]

    def test_tab_collapsed(self):
        assert re_mod.normalize_code_block("\t\thello") == ["hello"]

    def test_whitespace_runs_collapsed(self):
        assert re_mod.normalize_code_block("foo   bar\tbaz") == ["foo bar baz"]

    def test_leading_trailing_empties_stripped(self):
        assert re_mod.normalize_code_block("\n\n  \nfoo\n\n") == ["foo"]

    def test_internal_blank_preserved_as_empty_string(self):
        # internal blank lines collapse to "" (since " ".join("".split()) == "")
        result = re_mod.normalize_code_block("foo\n\nbar")
        assert result == ["foo", "", "bar"]

    def test_empty_input(self):
        assert re_mod.normalize_code_block("") == []
        assert re_mod.normalize_code_block("\n\n  ") == []


class TestNormalizeFileLines:
    def test_crlf_split(self):
        lines = re_mod.normalize_file_lines("a\r\nb\r\nc")
        assert lines == ["a", "b", "c"]

    def test_each_line_whitespace_collapsed(self):
        lines = re_mod.normalize_file_lines("\tfoo   bar\n\t\tbaz")
        assert lines == ["foo bar", "baz"]


# --------------------------------------------------------------------------- #
# parse_line
# --------------------------------------------------------------------------- #


class TestParseLine:
    def test_int(self):
        assert re_mod.parse_line(97, "ep") == (97, 97)

    def test_range(self):
        assert re_mod.parse_line("348-352", "ep") == (348, 352)

    def test_single_string_range(self):
        assert re_mod.parse_line("97-97", "ep") == (97, 97)

    def test_zero_int_rejected(self):
        with pytest.raises(re_mod.SchemaError):
            re_mod.parse_line(0, "ep")

    def test_negative_int_rejected(self):
        with pytest.raises(re_mod.SchemaError):
            re_mod.parse_line(-5, "ep")

    def test_zero_range_rejected(self):
        with pytest.raises(re_mod.SchemaError):
            re_mod.parse_line("0-5", "ep")

    def test_inverted_range_rejected(self):
        with pytest.raises(re_mod.SchemaError):
            re_mod.parse_line("10-5", "ep")

    def test_bool_rejected(self):
        with pytest.raises(re_mod.SchemaError):
            re_mod.parse_line(True, "ep")

    def test_garbage_string_rejected(self):
        with pytest.raises(re_mod.SchemaError):
            re_mod.parse_line("abc", "ep")

    def test_format_line_preserves_int(self):
        assert re_mod.format_line(10, 10, original_was_range=False) == 10

    def test_format_line_preserves_range(self):
        assert re_mod.format_line(10, 14, original_was_range=True) == "10-14"


# --------------------------------------------------------------------------- #
# Matchers
# --------------------------------------------------------------------------- #


class TestMatchers:
    def test_match_block_at_exact(self):
        file_norm = ["foo", "bar", "baz"]
        assert re_mod.match_block_at(file_norm, ["bar"], 2)

    def test_match_block_at_off_by_one(self):
        file_norm = ["foo", "bar", "baz"]
        assert not re_mod.match_block_at(file_norm, ["bar"], 1)
        assert not re_mod.match_block_at(file_norm, ["bar"], 3)

    def test_match_block_multiline(self):
        file_norm = ["x", "foo", "bar", "y"]
        assert re_mod.match_block_at(file_norm, ["foo", "bar"], 2)

    def test_match_block_out_of_range(self):
        file_norm = ["foo"]
        assert not re_mod.match_block_at(file_norm, ["foo"], 2)

    def test_match_block_zero_start_rejected(self):
        file_norm = ["foo"]
        assert not re_mod.match_block_at(file_norm, ["foo"], 0)

    def test_match_block_empty_code(self):
        assert not re_mod.match_block_at(["foo"], [], 1)

    def test_find_in_range_unique(self):
        file_norm = ["x", "foo", "y", "foo", "z"]
        assert re_mod.find_matches_in_range(file_norm, ["foo"], 1, 2) == [2]

    def test_find_in_range_multiple(self):
        file_norm = ["x", "foo", "y", "foo", "z"]
        assert re_mod.find_matches_in_range(file_norm, ["foo"], 1, 5) == [2, 4]

    def test_find_in_range_clamped(self):
        file_norm = ["x", "foo"]
        # range extends past end — must be clamped
        assert re_mod.find_matches_in_range(file_norm, ["foo"], 1, 100) == [2]

    def test_find_in_file_all(self):
        file_norm = ["foo", "bar", "foo"]
        assert re_mod.find_matches_in_file(file_norm, ["foo"]) == [1, 3]

    def test_find_in_file_multiline(self):
        file_norm = ["a", "foo", "bar", "b", "foo", "bar"]
        assert re_mod.find_matches_in_file(file_norm, ["foo", "bar"]) == [2, 5]

    def test_find_in_file_no_match(self):
        file_norm = ["a", "b"]
        assert re_mod.find_matches_in_file(file_norm, ["xyz"]) == []


# --------------------------------------------------------------------------- #
# Desc rewrite
# --------------------------------------------------------------------------- #


class TestDescRewrite:
    def test_no_anchors_returns_none(self):
        new, conflict = re_mod._rewrite_desc(
            "this desc has no positional info",
            old_file="a/b.ts", old_start=10,
            new_file="a/b.ts", new_start=11, new_end=11,
        )
        assert new is None
        assert conflict is False

    def test_zh_range_shifted(self):
        new, conflict = re_mod._rewrite_desc(
            "位于 foo.ts 第 10–20 行",
            old_file="a/foo.ts", old_start=10,
            new_file="a/foo.ts", new_start=12, new_end=22,
        )
        assert conflict is False
        assert "第 12–22 行" in new

    def test_zh_single_shifted(self):
        new, conflict = re_mod._rewrite_desc(
            "见第 42 行",
            old_file="a/foo.ts", old_start=42,
            new_file="a/foo.ts", new_start=45, new_end=45,
        )
        assert conflict is False
        assert "第 45 行" in new

    def test_en_range_shifted(self):
        new, conflict = re_mod._rewrite_desc(
            "see lines 10-20 for context",
            old_file="a/foo.ts", old_start=10,
            new_file="a/foo.ts", new_start=15, new_end=25,
        )
        assert conflict is False
        assert "lines 15-25" in new

    def test_bare_range_shifted(self):
        new, conflict = re_mod._rewrite_desc(
            "在 10-20 行处执行",
            old_file="a/foo.ts", old_start=10,
            new_file="a/foo.ts", new_start=11, new_end=21,
        )
        assert conflict is False
        assert "11-21 行" in new

    def test_file_anchor_same_file(self):
        new, conflict = re_mod._rewrite_desc(
            "in foo.ts we do X",
            old_file="a/foo.ts", old_start=10,
            new_file="a/foo.ts", new_start=10, new_end=10,
        )
        assert conflict is False
        assert "foo.ts" in new

    def test_file_anchor_renamed_path_only(self):
        # Same basename, different directory — path-only rename is safe
        new, conflict = re_mod._rewrite_desc(
            "in old.ts we do X",
            old_file="a/old.ts", old_start=10,
            new_file="b/old.ts", new_start=10, new_end=10,
        )
        assert conflict is False
        assert "old.ts" in new

    def test_file_anchor_basename_change_conflicts(self):
        # Different basename — cannot confidently map, must flag
        new, conflict = re_mod._rewrite_desc(
            "in old.ts we do X",
            old_file="a/old.ts", old_start=10,
            new_file="a/new.ts", new_start=10, new_end=10,
        )
        assert conflict is True
        assert new is None

    def test_file_anchor_unmappable_conflicts(self):
        # Old file basename does not appear in new file path
        new, conflict = re_mod._rewrite_desc(
            "in gone.ts we do X",
            old_file="a/gone.ts", old_start=10,
            new_file="a/other.ts", new_start=10, new_end=10,
        )
        # conflict because "gone.ts" anchor can't be mapped to "other.ts"
        assert conflict is True
        assert new is None

    def test_zh_step_not_treated_as_line(self):
        # 第 1 步 must not be shifted
        new, conflict = re_mod._rewrite_desc(
            "第 1 步：见 foo.ts 第 10 行",
            old_file="a/foo.ts", old_start=10,
            new_file="a/foo.ts", new_start=12, new_end=12,
        )
        assert conflict is False
        assert "第 1 步" in new
        assert "第 12 行" in new


# --------------------------------------------------------------------------- #
# Pipeline-level unit tests (no real git)
# --------------------------------------------------------------------------- #


def _make_file_with(content: str) -> list[str]:
    return re_mod.normalize_file_lines(content)


class TestPipelineStrategies:
    """Exercise repair_node via a stubbed RepoCache that returns canned content."""

    def _make_cache(self, files: dict[str, list[str]]) -> re_mod.RepoCache:
        cache = re_mod.RepoCache(Path("."), offline=True)
        ctx = re_mod.CommitContext(
            repo_url="r",
            commit="c" * 40,
            worktree=Path("."),
            base_repo=Path("."),
        )
        ctx._file_cache.update(files)

        # Patch index lazily; populate first_line_index immediately so
        # build_first_line_index returns it without scanning disk.
        idx: dict[str, list[tuple[str, int]]] = {}
        for rel, lines in files.items():
            for i, line in enumerate(lines):
                if line:
                    idx.setdefault(line, []).append((rel, i + 1))
        ctx._first_line_index = idx
        ctx._rels = tuple(files.keys())

        def fake_get(repo_url: str, commit: str):
            return ctx

        cache.get = fake_get  # type: ignore[method-assign]
        return cache

    def _node(self, **kw) -> re_mod.NodeRef:
        defaults = dict(
            entry_id="entry-00001",
            field_path="entry_point",
            file="a.ts",
            line_raw=1,
            code="foo",
            desc=None,
        )
        defaults.update(kw)
        return re_mod.NodeRef(**defaults)

    def test_original_position_match(self):
        cache = self._make_cache({"a.ts": ["foo", "bar", "baz"]})
        node = self._node(file="a.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        # original-position match: strategy/reason both None
        assert out.strategy is None
        assert out.reason is None
        assert out.new_file == "a.ts"
        assert out.new_start == 1

    def test_nearby_unique(self):
        cache = self._make_cache({"a.ts": ["x", "y", "foo", "bar"]})
        # original annotation says line 1; code actually at line 3 (within ±5)
        node = self._node(file="a.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy == re_mod.STRATEGY_NEARBY
        assert out.new_start == 3
        assert out.new_file == "a.ts"

    def test_multiple_nearby_needs_human(self):
        # "foo" at lines 1 and 3; annotation at line 2 (x) — original fails,
        # both candidates within ±5
        cache = self._make_cache({"a.ts": ["foo", "x", "foo"]})
        node = self._node(file="a.ts", line_raw=2, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_MULTIPLE_NEARBY
        assert len(out.candidates) == 2

    def test_file_unique(self):
        # code at line 10, no nearby match (annotation at line 1, far away)
        lines = ["z"] * 9 + ["foo"]
        cache = self._make_cache({"a.ts": lines})
        node = self._node(file="a.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy == re_mod.STRATEGY_FILE
        assert out.new_start == 10

    def test_multiple_file_needs_human(self):
        # "foo" at lines 1 and 15; annotation at line 8 (outside ±5 of both)
        # so nearby finds 0, file-wide finds 2
        lines = ["foo"] + ["x"] * 13 + ["foo"]
        cache = self._make_cache({"a.ts": lines})
        node = self._node(file="a.ts", line_raw=8, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_MULTIPLE_FILE

    def test_repo_unique_when_file_missing(self):
        cache = self._make_cache({
            "a.ts": ["x", "y"],
            "b.ts": ["alpha", "foo", "beta"],
        })
        node = self._node(file="missing.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy == re_mod.STRATEGY_REPO
        assert out.new_file == "b.ts"
        assert out.new_start == 2

    def test_repo_unique_when_original_file_has_zero(self):
        cache = self._make_cache({
            "a.ts": ["x", "y"],
            "b.ts": ["alpha", "foo", "beta"],
        })
        node = self._node(file="a.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy == re_mod.STRATEGY_REPO
        assert out.new_file == "b.ts"

    def test_multiple_repo_needs_human(self):
        cache = self._make_cache({
            "a.ts": ["x"],
            "b.ts": ["foo"],
            "c.ts": ["foo"],
        })
        node = self._node(file="a.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_MULTIPLE_REPO
        assert len(out.candidates) == 2

    def test_code_not_found(self):
        cache = self._make_cache({
            "a.ts": ["x", "y"],
            "b.ts": ["alpha", "beta"],
        })
        node = self._node(file="a.ts", line_raw=1, code="zzz")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_CODE_NOT_FOUND

    def test_file_not_found(self):
        cache = self._make_cache({"a.ts": ["foo"]})
        node = self._node(file="ghost.ts", line_raw=1, code="zzz")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_FILE_NOT_FOUND

    def test_empty_code_needs_human(self):
        cache = self._make_cache({"a.ts": ["foo"]})
        node = self._node(file="a.ts", line_raw=1, code="   \n  \n")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_EMPTY_CODE

    def test_repo_unavailable_offline(self):
        cache = re_mod.RepoCache(Path("."), offline=True)
        # No worktree, no fetch
        node = self._node(file="a.ts", line_raw=1, code="foo")
        out = re_mod.repair_node(
            node,
            repo_url="https://github.com/nonexistent/nop",
            commit="0" * 40,
            cache=cache,
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_REPO_UNAVAILABLE

    def test_multiline_code_match(self):
        cache = self._make_cache({"a.ts": ["x", "alpha", "beta", "gamma", "y"]})
        node = self._node(
            file="a.ts",
            line_raw=1,
            code="alpha\nbeta\ngamma",
        )
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        # original position fails (line 1), nearby finds at line 2
        assert out.strategy == re_mod.STRATEGY_NEARBY
        assert out.new_start == 2

    def test_range_line_preserved_as_range(self):
        lines = ["x"] * 9 + ["alpha", "beta"]
        cache = self._make_cache({"a.ts": lines})
        node = self._node(
            file="a.ts",
            line_raw="1-2",
            code="alpha\nbeta",
        )
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy == re_mod.STRATEGY_FILE
        assert out.new_start == 10
        # end should be 11 for 2-line block
        assert out.new_end == 11

    def test_low_info_brace_needs_human_when_multiple(self):
        # single-line } appears at lines 2 and 4; annotation at line 1
        # (which is "{", so original fails) — both within ±5
        cache = self._make_cache({"a.ts": ["{", "}", "{", "}"]})
        node = self._node(file="a.ts", line_raw=1, code="}")
        out = re_mod.repair_node(
            node, repo_url="r", commit="c" * 40, cache=cache
        )
        assert out.strategy is None
        assert out.reason == re_mod.REASON_MULTIPLE_NEARBY


# --------------------------------------------------------------------------- #
# CSV escaping
# --------------------------------------------------------------------------- #


class TestCSVEscaping:
    def test_fix_diff_csv_handles_multiline_and_unicode(self, tmp_path):
        node = re_mod.NodeRef(
            entry_id="entry-00001",
            field_path="trace[0]",
            file="a.ts",
            line_raw=10,
            code="foo\nbar",
            desc="中文描述 第 10 行",
        )
        out = re_mod.Outcome(
            node=node,
            strategy=re_mod.STRATEGY_NEARBY,
            reason=None,
            new_file="a.ts",
            new_start=11,
            new_end=12,
            new_desc="中文描述 第 11 行",
            candidates=[("a.ts", 11)],
        )
        path = tmp_path / "fix.csv"
        n = re_mod.write_fix_diff_csv([out], path)
        assert n == 1
        text = path.read_text(encoding="utf-8")
        # Parse back
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 1
        row = rows[0]
        assert row["entry_id"] == "entry-00001"
        assert row["old_file"] == "a.ts"
        assert row["old_line"] == "10"
        assert row["new_line"] == "11"
        assert "中文描述" in row["new_desc"]
        assert row["strategy"] == re_mod.STRATEGY_NEARBY

    def test_needs_human_csv_handles_quotes(self, tmp_path):
        node = re_mod.NodeRef(
            entry_id='entry-x',
            field_path="critical_operation",
            file='a/b.ts',
            line_raw=10,
            code='console.log("hi")',
            desc=None,
        )
        out = re_mod.Outcome(
            node=node,
            strategy=None,
            reason=re_mod.REASON_MULTIPLE_FILE,
            candidates=[("a/b.ts", 5), ("a/b.ts", 9)],
        )
        path = tmp_path / "nh.csv"
        n = re_mod.write_needs_human_csv([out], path)
        assert n == 1
        reader = csv.DictReader(io.StringIO(path.read_text(encoding="utf-8")))
        rows = list(reader)
        assert rows[0]["code"] == 'console.log("hi")'
        assert rows[0]["candidate_count"] == "2"


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


class TestSchemaValidation:
    def _valid_entry(self) -> dict:
        return {
            "commit": "a" * 40,
            "critical_operation": {"file": "a.ts", "line": 1, "code": "x"},
            "entry_id": "entry-00001",
            "entry_point": {"file": "a.ts", "line": 1, "code": "x"},
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "p",
            "repo_url": "https://github.com/o/p",
            "report_id": "GHSA-AAAA-BBBB-CCCC",
            "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "trace": [],
            "verify": 1,
            "vuln_category_l1": "XSS",
            "vuln_category_l2": "Stored XSS",
            "vuln_ids": [],
            "vuln_title": "t",
        }

    def test_valid_entry_passes(self):
        re_mod.validate_entry(0, self._valid_entry())

    def test_missing_required_key(self):
        e = self._valid_entry()
        del e["commit"]
        with pytest.raises(re_mod.SchemaError):
            re_mod.validate_entry(0, e)

    def test_forbidden_internal_key(self):
        e = self._valid_entry()
        e["description"] = "extra"
        with pytest.raises(re_mod.SchemaError):
            re_mod.validate_entry(0, e)

    def test_bad_commit(self):
        e = self._valid_entry()
        e["commit"] = "xyz"
        with pytest.raises(re_mod.SchemaError):
            re_mod.validate_entry(0, e)

    def test_bad_verify(self):
        e = self._valid_entry()
        e["verify"] = 2
        with pytest.raises(re_mod.SchemaError):
            re_mod.validate_entry(0, e)

    def test_node_missing_code(self):
        e = self._valid_entry()
        del e["entry_point"]["code"]
        with pytest.raises(re_mod.SchemaError):
            re_mod.validate_entry(0, e)

    def test_node_line_zero(self):
        e = self._valid_entry()
        e["entry_point"]["line"] = 0
        with pytest.raises(re_mod.SchemaError):
            re_mod.validate_entry(0, e)


# --------------------------------------------------------------------------- #
# Integration: real git repository
# --------------------------------------------------------------------------- #


def _git(args: list[str], cwd: Path) -> str:
    res = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    assert res.returncode == 0, f"git {args} failed: {res.stderr}"
    return res.stdout


@pytest.fixture
def two_commit_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """Build a tiny repo with two commits so we can verify commit-specific lookups."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], repo)

    # Commit 1: original layout
    (repo / "a.ts").write_text("line1\nfoo\nline3\nbar\nline5\n", encoding="utf-8")
    (repo / "b.ts").write_text("alpha\nbeta\n", encoding="utf-8")
    _git(["add", "."], repo)
    _git(["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "c1"], repo)
    sha1 = _git(["rev-parse", "HEAD"], repo).strip()

    # Commit 2: shift lines by inserting a header
    (repo / "a.ts").write_text(
        "header1\nheader2\nline1\nfoo\nline3\nbar\nline5\n", encoding="utf-8"
    )
    _git(["add", "."], repo)
    _git(["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "c2"], repo)
    sha2 = _git(["rev-parse", "HEAD"], repo).strip()

    return repo, sha1, sha2


class TestIntegrationTwoCommits:
    def test_uses_correct_commit_not_head(self, two_commit_repo, tmp_path):
        repo, sha1, sha2 = two_commit_repo
        # Annotation from commit 1 says "foo" is at line 2 — correct for c1,
        # wrong for c2 (where "foo" is at line 4). Verify the cache uses c1.
        cache_root = tmp_path / "cache"
        cache_root.mkdir()
        # Mirror VulnGym layout: <org>__<repo>__<commit8>/
        slug = "test__repo"
        wt = cache_root / f"{slug}__{sha1[:8]}"
        _git(["worktree", "add", "--detach", str(wt), sha1], repo)

        cache = re_mod.RepoCache(cache_root, offline=True)
        ctx = cache.get("https://github.com/test/repo", sha1)
        assert ctx is not None
        lines = ctx.read_file("a.ts")
        # On commit 1, "foo" is at line 2. On commit 2 it would be at line 4.
        # Verify the cache actually serves commit 1, not HEAD (= commit 2).
        assert lines[1] == "foo"
        assert lines[3] == "bar"  # commit 1 line 4 is "bar", not "foo"

    def test_repair_uses_correct_commit(self, two_commit_repo, tmp_path):
        repo, sha1, sha2 = two_commit_repo
        cache_root = tmp_path / "cache"
        cache_root.mkdir()
        slug = "test__repo"
        wt = cache_root / f"{slug}__{sha1[:8]}"
        _git(["worktree", "add", "--detach", str(wt), sha1], repo)

        cache = re_mod.RepoCache(cache_root, offline=True)
        # Annotation says "foo" at line 1 of a.ts. Actual position in c1 is 2.
        # Nearby ±5 should find it at line 2.
        node = re_mod.NodeRef(
            entry_id="e",
            field_path="entry_point",
            file="a.ts",
            line_raw=1,
            code="foo",
            desc=None,
        )
        out = re_mod.repair_node(
            node,
            repo_url="https://github.com/test/repo",
            commit=sha1,
            cache=cache,
        )
        assert out.strategy == re_mod.STRATEGY_NEARBY
        assert out.new_start == 2


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


class TestDeterminism:
    def test_two_runs_produce_identical_output(self, tmp_path):
        """Build a tiny entry list, run pipeline twice, byte-compare."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(["init"], repo)
        (repo / "a.ts").write_text(
            "alpha\nfoo\nbeta\ngamma\n", encoding="utf-8"
        )
        _git(["add", "."], repo)
        _git(
            ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"],
            repo,
        )
        sha = _git(["rev-parse", "HEAD"], repo).strip()

        cache_root = tmp_path / "cache"
        cache_root.mkdir()
        slug = "test__repo"
        wt = cache_root / f"{slug}__{sha[:8]}"
        _git(["worktree", "add", "--detach", str(wt), sha], repo)

        entry = {
            "commit": sha,
            "critical_operation": {
                "file": "a.ts", "line": 5, "code": "foo",
            },
            "entry_id": "entry-00001",
            "entry_point": {
                "file": "a.ts", "line": 5, "code": "foo",
            },
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "p",
            "repo_url": "https://github.com/test/repo",
            "report_id": "GHSA-AAAA-BBBB-CCCC",
            "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "trace": [],
            "verify": 0,
            "vuln_category_l1": "XSS",
            "vuln_category_l2": "Stored XSS",
            "vuln_ids": [],
            "vuln_title": "t",
        }
        src = tmp_path / "entries.jsonl"
        src.write_text(json.dumps(entry, ensure_ascii=False) + "\n", encoding="utf-8")

        def _run(outdir: Path):
            return re_mod.run(
                input_path=src,
                output_jsonl=outdir / "fixed.jsonl",
                fix_diff_csv=outdir / "fix.csv",
                needs_human_csv=outdir / "nh.csv",
                cache_dir=cache_root,
                only_unverified=False,
                offline=True,
            )

        out1 = tmp_path / "run1"
        out2 = tmp_path / "run2"
        out1.mkdir()
        out2.mkdir()
        stats1 = _run(out1)
        stats2 = _run(out2)
        assert stats1 == stats2

        for name in ("fixed.jsonl", "fix.csv", "nh.csv"):
            a = (out1 / name).read_bytes()
            b = (out2 / name).read_bytes()
            assert a == b, f"{name} differs between runs"


# --------------------------------------------------------------------------- #
# JSONL output format
# --------------------------------------------------------------------------- #


class TestJSONLOutput:
    def test_keys_sorted_and_utf8_preserved(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(["init"], repo)
        (repo / "a.ts").write_text("foo\n", encoding="utf-8")
        _git(["add", "."], repo)
        _git(
            ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"],
            repo,
        )
        sha = _git(["rev-parse", "HEAD"], repo).strip()
        cache_root = tmp_path / "cache"
        cache_root.mkdir()
        slug = "test__repo"
        wt = cache_root / f"{slug}__{sha[:8]}"
        _git(["worktree", "add", "--detach", str(wt), sha], repo)

        entry = {
            "commit": sha,
            "critical_operation": {
                "file": "a.ts", "line": 1, "code": "foo",
                "desc": "中文 第 1 行",
            },
            "entry_id": "entry-00001",
            "entry_point": {
                "file": "a.ts", "line": 1, "code": "foo",
                "desc": "中文 第 1 行",
            },
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "p",
            "repo_url": "https://github.com/test/repo",
            "report_id": "GHSA-AAAA-BBBB-CCCC",
            "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "trace": [],
            "verify": 0,
            "vuln_category_l1": "XSS",
            "vuln_category_l2": "Stored XSS",
            "vuln_ids": [],
            "vuln_title": "t",
        }
        src = tmp_path / "entries.jsonl"
        src.write_text(json.dumps(entry, ensure_ascii=False) + "\n", encoding="utf-8")
        out_jsonl = tmp_path / "fixed.jsonl"

        re_mod.run(
            input_path=src,
            output_jsonl=out_jsonl,
            fix_diff_csv=tmp_path / "fix.csv",
            needs_human_csv=tmp_path / "nh.csv",
            cache_dir=cache_root,
            offline=True,
        )

        # Read raw bytes to verify UTF-8 preservation
        raw = out_jsonl.read_bytes().decode("utf-8").strip()
        obj = json.loads(raw)
        # Sorted keys: commit comes before critical_operation alphabetically
        keys = list(obj.keys())
        assert keys == sorted(keys)
        # UTF-8 preservation
        assert "中文" in obj["entry_point"]["desc"]
