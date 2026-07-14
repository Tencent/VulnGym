from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "location_review.py"
SPEC = importlib.util.spec_from_file_location("location_review", SCRIPT)
assert SPEC and SPEC.loader
review = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = review
SPEC.loader.exec_module(review)


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


class LocationReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo_url = "https://github.com/acme/demo"
        self.work = self.root / "source"
        self.work.mkdir()
        git("init", "-q", cwd=self.work)
        git("config", "user.email", "review@example.com", cwd=self.work)
        git("config", "user.name", "Review Test", cwd=self.work)
        source = self.work / "src" / "app.ts"
        source.parent.mkdir()
        source.write_text(
            "const header = true;\n"
            "const value = input;\n"
            'const url = "http://example.test/# 中文";\n'
            "return value;\n",
            encoding="utf-8",
        )
        git("add", "src/app.ts", cwd=self.work)
        git("commit", "-q", "-m", "fixture", cwd=self.work)
        self.commit = git("rev-parse", "HEAD", cwd=self.work)

        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.bare = self.cache / review.cache_name(self.repo_url)
        git("clone", "-q", "--bare", str(self.work), str(self.bare), cwd=self.root)
        git(
            "remote",
            "set-url",
            "origin",
            f"{self.repo_url}.git",
            cwd=self.bare,
        )
        git(
            "update-ref",
            f"{review.PROVENANCE_REF_PREFIX}/{self.commit}",
            self.commit,
            cwd=self.bare,
        )

        self.input = self.root / "entries.jsonl"
        self.queue = self.root / "needs_human.csv"
        self.decisions = self.root / "decisions.csv"
        self.output = self.root / "entries.reviewed.jsonl"
        self.diff = self.root / "review.diff.csv"
        self.audit = self.root / "review.audit.csv"
        self.entry = self.make_entry()
        self.write_entries([self.entry])
        self.write_queue()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_entry(self, *, verify: int = 0) -> dict:
        return {
            "entry_id": "entry-00001",
            "repo_url": self.repo_url,
            "commit": self.commit,
            "verify": verify,
            "entry_point": {
                "file": "src/app.ts",
                "line": 1,
                "code": "const value = input; // 人工补充说明",
                "desc": "app.ts 第 1 行接收输入。",
            },
            "critical_operation": {
                "file": "src/app.ts",
                "line": 4,
                "code": "return value;",
                "desc": "返回值。",
            },
            "trace": [],
        }

    def write_entries(self, entries: list[dict]) -> None:
        with self.input.open("w", encoding="utf-8", newline="\n") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    def write_queue(self, rows: list[dict[str, str]] | None = None) -> None:
        rows = rows or [
            {
                "entry_id": "entry-00001",
                "field_path": "entry_point",
                "reason": "multiple_matches",
                "details": "two candidates require a human decision",
            }
        ]
        with self.queue.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["entry_id", "field_path", "reason", "details"],
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)

    def initialize(self) -> list[dict[str, str]]:
        count = review.initialize_decisions(self.input, self.queue, self.decisions)
        self.assertEqual(count, 1)
        with self.decisions.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def write_decisions(self, rows: list[dict[str, str]]) -> None:
        review.atomic_write_csv(self.decisions, review.DECISION_FIELDS, rows)

    def apply(self, **overrides):
        arguments = {
            "input_path": self.input,
            "decisions_path": self.decisions,
            "output_path": self.output,
            "diff_path": self.diff,
            "audit_path": self.audit,
            "cache_root": self.cache,
            "offline": True,
        }
        arguments.update(overrides)
        return review.apply_decisions(**arguments)

    def complete_apply(self, rows: list[dict[str, str]], *, line: str = "2") -> None:
        rows[0].update(
            {
                "decision": "apply",
                "new_file": "src/app.ts",
                "new_line": line,
                "reviewer": "alice",
                "rationale": "selected after comparing both candidates",
            }
        )
        self.write_decisions(rows)

    def test_init_creates_stable_fingerprinted_decision(self) -> None:
        first = self.initialize()
        expected_sha = review.node_sha256(
            self.entry, "entry_point", self.entry["entry_point"]
        )
        self.assertEqual(first[0]["expected_node_sha256"], expected_sha)
        self.assertEqual(first[0]["review_id"], f"loc-{expected_sha[:20]}")
        self.assertEqual(first[0]["reason"], "multiple_matches")
        review.initialize_decisions(self.input, self.queue, self.decisions)
        second = self.initialize()
        self.assertEqual(first, second)

    def test_apply_validates_blob_and_rewrites_explicit_desc_anchor(self) -> None:
        rows = self.initialize()
        self.complete_apply(rows)
        self.assertEqual(self.apply(), (1, 0, 0))
        fixed = review.read_jsonl(self.output)[0]
        node = fixed["entry_point"]
        self.assertEqual(node["line"], 2)
        self.assertEqual(node["desc"], "app.ts 第 2 行接收输入。")
        _, diff_rows = review.read_csv(self.diff)
        self.assertEqual(diff_rows[0]["match_mode"], "annotator_comment_projection")
        self.assertRegex(diff_rows[0]["source_blob_oid"], r"^[0-9a-f]{40}$")
        self.assertRegex(diff_rows[0]["source_sha256"], r"^[0-9a-f]{64}$")

    def test_stale_decision_is_rejected_without_touching_outputs(self) -> None:
        rows = self.initialize()
        self.complete_apply(rows)
        changed = self.make_entry()
        changed["entry_point"]["desc"] = "annotation changed after review initialization"
        self.write_entries([changed])
        self.output.write_text("sentinel", encoding="utf-8")
        with self.assertRaisesRegex(review.ReviewError, "stale decision"):
            self.apply()
        self.assertEqual(self.output.read_text(encoding="utf-8"), "sentinel")
        self.assertFalse(self.diff.exists())
        self.assertFalse(self.audit.exists())

    def test_pending_rows_fail_closed_unless_explicitly_allowed(self) -> None:
        self.initialize()
        with self.assertRaisesRegex(review.ReviewError, "still pending"):
            self.apply()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.apply(allow_pending=True), (0, 0, 1))
        self.assertEqual(review.read_jsonl(self.output), [self.entry])

    def test_keep_decision_records_audit_without_source_access(self) -> None:
        rows = self.initialize()
        rows[0].update(
            {
                "decision": "keep",
                "reviewer": "alice",
                "rationale": "neither candidate is sufficiently supported",
            }
        )
        self.write_decisions(rows)
        missing_cache = self.root / "not-created"
        self.assertEqual(self.apply(cache_root=missing_cache), (0, 1, 0))
        _, audit_rows = review.read_csv(self.audit)
        self.assertEqual(audit_rows[0]["status"], "kept")
        self.assertFalse(missing_cache.exists())

    def test_verified_entries_are_protected_by_default(self) -> None:
        verified = self.make_entry(verify=1)
        self.write_entries([verified])
        rows = self.initialize()
        self.complete_apply(rows)
        with self.assertRaisesRegex(review.ReviewError, "verify=1 is protected"):
            self.apply()
        self.assertEqual(self.apply(include_verified=True), (1, 0, 0))

    def test_path_escape_and_case_drift_are_rejected(self) -> None:
        rows = self.initialize()
        self.complete_apply(rows)
        rows[0]["new_file"] = "../src/app.ts"
        self.write_decisions(rows)
        with self.assertRaisesRegex(review.SourceError, "unsafe repository path"):
            self.apply()

        rows[0]["new_file"] = "src/App.ts"
        self.write_decisions(rows)
        with self.assertRaisesRegex(review.SourceError, "exact case"):
            self.apply()

    def test_wrong_source_location_is_rejected(self) -> None:
        rows = self.initialize()
        self.complete_apply(rows, line="4")
        with self.assertRaisesRegex(review.SourceError, "does not match"):
            self.apply()

    def test_apply_requires_a_real_location_change(self) -> None:
        rows = self.initialize()
        self.complete_apply(rows, line="1")
        with self.assertRaisesRegex(review.ReviewError, "use keep"):
            self.apply()

    def test_outputs_cannot_overwrite_inputs_or_each_other(self) -> None:
        self.initialize()
        with self.assertRaisesRegex(review.ReviewError, "must not overwrite the input"):
            self.apply(output_path=self.input, allow_pending=True)
        with self.assertRaisesRegex(review.ReviewError, "must be different"):
            self.apply(diff_path=self.output, allow_pending=True)

    def test_ranges_must_end_at_the_snippet_boundary(self) -> None:
        text = (self.work / "src" / "app.ts").read_text(encoding="utf-8")
        code = "const value = input;\nconst url = \"http://example.test/# 中文\";"
        self.assertEqual(
            review.match_source(code, text, review.LineSpan(2, 3)),
            "normalized_exact",
        )
        with self.assertRaisesRegex(review.SourceError, "snippet ends at 3"):
            review.match_source(code, text, review.LineSpan(2, 4))

    def test_comment_markers_inside_strings_are_not_projected(self) -> None:
        code = 'const url = "http://example.test/# 中文";'
        self.assertIsNone(review.annotation_comment_index(code))
        text = (self.work / "src" / "app.ts").read_text(encoding="utf-8")
        self.assertEqual(
            review.match_source(code, text, review.LineSpan(3, 3)),
            "normalized_exact",
        )

    def test_annotation_only_code_is_not_accepted_as_evidence(self) -> None:
        self.assertIsNone(review.projected_annotation_lines("// 人工说明"))
        with self.assertRaisesRegex(review.SourceError, "does not match"):
            review.match_source("// 人工说明", "\n", review.LineSpan(1, 1))

    def test_cache_keys_isolate_repositories_with_the_same_name(self) -> None:
        first = review.cache_name("https://github.com/jlowin/fastmcp")
        second = review.cache_name("https://github.com/PrefectHQ/fastmcp")
        self.assertNotEqual(first, second)
        self.assertIn("jlowin__fastmcp", first)
        self.assertIn("PrefectHQ__fastmcp", second)

    def test_offline_cache_rejects_unprovenanced_commit_objects(self) -> None:
        git(
            "update-ref",
            "-d",
            f"{review.PROVENANCE_REF_PREFIX}/{self.commit}",
            cwd=self.bare,
        )
        cache = review.GitBlobCache(self.repo_url, self.cache, offline=True)
        with self.assertRaisesRegex(review.SourceError, "not provenance-verified"):
            cache.read_blob(self.commit, "src/app.ts")

    def test_duplicate_queue_rows_are_rejected(self) -> None:
        row = {
            "entry_id": "entry-00001",
            "field_path": "entry_point",
            "reason": "multiple_matches",
            "details": "",
        }
        self.write_queue([row, row])
        with self.assertRaisesRegex(review.ReviewError, "duplicate queue row"):
            review.initialize_decisions(self.input, self.queue, self.decisions)

    def test_init_accepts_node_path_used_by_other_repair_queues(self) -> None:
        with self.queue.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["entry_id", "node_path", "reason"],
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerow(
                {
                    "entry_id": "entry-00001",
                    "node_path": "entry_point",
                    "reason": "multiple_matches",
                }
            )
        rows = self.initialize()
        self.assertEqual(rows[0]["field_path"], "entry_point")


if __name__ == "__main__":
    unittest.main()
