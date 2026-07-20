from __future__ import annotations

import copy
import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repair_code_locations",
    ROOT / "scripts" / "repair_code_locations.py",
)
assert SPEC and SPEC.loader
repair = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = repair
SPEC.loader.exec_module(repair)

VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_code_location_outputs",
    ROOT / "scripts" / "verify_code_location_outputs.py",
)
assert VERIFY_SPEC and VERIFY_SPEC.loader
verify = importlib.util.module_from_spec(VERIFY_SPEC)
sys.modules[VERIFY_SPEC.name] = verify
VERIFY_SPEC.loader.exec_module(verify)


REPO = "https://github.com/example/project"
COMMIT = "a" * 40


def node(
    *,
    file: str = "src/app.py",
    line: int | str = 1,
    code: str = "danger()",
    desc: str = "",
) -> dict:
    value = {"file": file, "line": line, "code": code}
    if desc:
        value["desc"] = desc
    return value


def entry(
    *,
    entry_id: str = "entry-00001",
    verify: int = 0,
    target: dict | None = None,
) -> dict:
    target = target or node()
    return {
        "commit": COMMIT,
        "critical_operation": copy.deepcopy(target),
        "entry_id": entry_id,
        "entry_point": copy.deepcopy(target),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "project",
        "repo_url": REPO,
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "trace": [],
        "verify": verify,
        "vuln_category_l1": "test",
        "vuln_category_l2": "test",
        "vuln_ids": ["CVE-2026-0001"],
        "vuln_title": "test",
    }


def ref(
    target: dict,
    *,
    verify: int = 0,
    field_path: str = "entry_point",
) -> repair.NodeRef:
    return repair.NodeRef(
        entry_index=0,
        entry_id="entry-00001",
        verify=verify,
        repo_url=REPO,
        commit=COMMIT,
        field_path=field_path,
        node=target,
    )


class FakeCache:
    def __init__(
        self,
        files: dict[tuple[str, str, str], str | None],
        repo_matches: dict[tuple[str, ...], list[repair.SourceMatch]] | None = None,
        snapshot: bool = True,
    ) -> None:
        self.files = files
        self.repo_matches = repo_matches or {}
        self.snapshot = Path("/snapshot") if snapshot else None

    def read_file(self, repo_url: str, commit: str, file: str) -> str | None:
        return self.files.get((repo_url, commit, file))

    def search_repository(
        self,
        repo_url: str,
        commit: str,
        pattern: repair.CodePattern,
        *,
        limit: int = 64,
    ) -> list[repair.SourceMatch]:
        return self.repo_matches.get(pattern.lines, [])

    def ensure_snapshot(self, repo_url: str, commit: str) -> Path | None:
        return self.snapshot


class LineAndPatternTests(unittest.TestCase):
    def test_integer_line_is_a_start_anchor(self):
        span = repair.LineSpan.parse(8)
        match = repair.SourceMatch("x.py", 8, 10, "verbatim")
        self.assertTrue(span.contains_match(match))
        self.assertEqual(span.render_match(match), 8)

    def test_range_requires_exact_start_and_end(self):
        span = repair.LineSpan.parse("8-10")
        self.assertTrue(
            span.contains_match(repair.SourceMatch("x.py", 8, 10, "verbatim"))
        )
        self.assertFalse(
            span.contains_match(repair.SourceMatch("x.py", 8, 9, "verbatim"))
        )

    def test_invalid_line_values_are_rejected(self):
        for value in (True, 0, -1, "0-1", "3-2", "1", ""):
            with self.subTest(value=value):
                with self.assertRaises(repair.RepairError):
                    repair.LineSpan.parse(value)

    def test_whitespace_normalization_preserves_line_boundaries(self):
        self.assertEqual(
            repair.normalize_code("\n  one(\t a )  \n\n two() \n"),
            ("one( a )", "", "two()"),
        )

    def test_projection_removes_only_cjk_annotation_suffix(self):
        patterns = repair.build_patterns("danger(value); // 这里是危险调用")
        self.assertEqual(len(patterns), 2)
        self.assertEqual(patterns[0].lines, ("danger(value); // 这里是危险调用",))
        self.assertEqual(patterns[1].lines, ("danger(value);",))

    def test_non_cjk_source_comment_is_not_projected(self):
        patterns = repair.build_patterns("danger(); // keep this source comment")
        self.assertEqual(len(patterns), 1)

    def test_pure_cjk_annotation_line_is_removed(self):
        patterns = repair.build_patterns(
            "first()\n// 此行为标注者说明\nsecond()"
        )
        self.assertEqual(patterns[1].lines, ("first()", "second()"))

    def test_ellipsis_is_never_treated_as_a_wildcard(self):
        patterns = repair.build_patterns("first()\n...\nlast()")
        self.assertEqual(patterns[1].unsafe_reason, "ellipsis_not_expanded")

    def test_low_information_detection(self):
        self.assertTrue(repair.is_low_information(("}",)))
        self.assertTrue(repair.is_low_information(("return",)))
        self.assertFalse(repair.is_low_information(("danger(value)",)))

    def test_repository_paths_are_confined(self):
        self.assertEqual(repair.normalize_repo_path("./src/app.py"), "src/app.py")
        for value in ("../secret", "/etc/passwd", "src/../../secret", ""):
            with self.subTest(value=value):
                with self.assertRaises(repair.RepairError):
                    repair.normalize_repo_path(value)


class ResolverTests(unittest.TestCase):
    def cache(self, text: str | None) -> FakeCache:
        return FakeCache({(REPO, COMMIT, "src/app.py"): text})

    def test_multiline_code_at_integer_start_is_already_matched(self):
        target = node(line=2, code="first()\nsecond()")
        result = repair.resolve_original_file(
            ref(target),
            self.cache("header\nfirst()\nsecond()\ntail\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "matched")
        self.assertEqual(result.match.start, 2)
        self.assertEqual(result.match.end, 3)

    def test_low_information_code_is_accepted_only_at_current_location(self):
        current = node(line=2, code="}")
        result = repair.resolve_original_file(
            ref(current),
            self.cache("header\n}\ntail\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "matched")

        shifted = node(line=1, code="}")
        result = repair.resolve_original_file(
            ref(shifted),
            self.cache("header\n}\ntail\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(result.reason, "low_information_code")

    def test_wrong_range_end_is_repaired_to_natural_span(self):
        target = node(line="2-4", code="first()\nsecond()")
        result = repair.resolve_original_file(
            ref(target),
            self.cache("header\nfirst()\nsecond()\ntail\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "fixed")
        self.assertEqual(result.match.start, 2)
        self.assertEqual(result.match.end, 3)

    def test_shifted_range_does_not_inherit_the_old_width(self):
        target = node(line="1-4", code="first()\nsecond()")
        result = repair.resolve_original_file(
            ref(target),
            self.cache("header\nfirst()\nsecond()\ntail\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.match.line_value, "2-3")

    def test_unique_nearby_match_is_fixed(self):
        target = node(line=1, code="danger(value)")
        result = repair.resolve_original_file(
            ref(target),
            self.cache("header\ndanger(value)\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual((result.status, result.stage), ("fixed", "nearby"))

    def test_multiple_nearby_matches_require_human_review(self):
        target = node(line=2, code="danger(value)")
        result = repair.resolve_original_file(
            ref(target),
            self.cache("danger(value)\nheader\ndanger(value)\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(result.reason, "multiple_nearby_matches")

    def test_unique_same_file_match_is_fixed(self):
        target = node(line=1, code="danger(value)")
        text = "\n".join(["header"] * 10 + ["danger(value)"])
        result = repair.resolve_original_file(
            ref(target),
            self.cache(text),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual((result.status, result.stage), ("fixed", "same_file"))

    def test_projection_can_confirm_current_unverified_location(self):
        target = node(line=2, code="danger(); // 这里是标注")
        result = repair.resolve_original_file(
            ref(target),
            self.cache("header\ndanger();\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "matched")
        self.assertEqual(result.match_mode, "annotation_projection")

    def test_projected_verified_repair_requires_human_review(self):
        target = node(line=1, code="danger(); // 这里是标注")
        result = repair.resolve_original_file(
            ref(target, verify=1),
            self.cache("header\ndanger();\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(
            result.reason, "verified_entry_requires_verbatim_match"
        )

    def test_verbatim_verified_repair_is_allowed_in_strict_policy(self):
        target = node(line=1, code="danger(value)")
        result = repair.resolve_original_file(
            ref(target, verify=1),
            self.cache("header\ndanger(value)\n"),
            nearby=5,
            verified_policy="strict",
        )
        self.assertEqual(result.status, "fixed")

    def test_protect_policy_blocks_verified_repair(self):
        target = node(line=1, code="danger(value)")
        result = repair.resolve_original_file(
            ref(target, verify=1),
            self.cache("header\ndanger(value)\n"),
            nearby=5,
            verified_policy="protect",
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(result.reason, "verified_entry_protected")

    def test_repository_unique_match_repairs_file_and_line(self):
        target = node(file="missing.py", line=10, code="danger(value)")
        cache = FakeCache(
            {(REPO, COMMIT, "missing.py"): None},
            {
                ("danger(value)",): [
                    repair.SourceMatch(
                        "src/actual.py", 7, 7, "verbatim"
                    )
                ]
            },
        )
        first = repair.resolve_original_file(
            ref(target), cache, nearby=5, verified_policy="strict"
        )
        result = repair.resolve_repository(
            first, cache, verified_policy="strict"
        )
        self.assertEqual((result.status, result.stage), ("fixed", "repository"))
        self.assertEqual(result.match.file, "src/actual.py")

    def test_repository_ambiguity_is_not_guessed(self):
        target = node(file="missing.py", line=10, code="danger(value)")
        cache = FakeCache(
            {(REPO, COMMIT, "missing.py"): None},
            {
                ("danger(value)",): [
                    repair.SourceMatch("a.py", 1, 1, "verbatim"),
                    repair.SourceMatch("b.py", 2, 2, "verbatim"),
                ]
            },
        )
        first = repair.resolve_original_file(
            ref(target), cache, nearby=5, verified_policy="strict"
        )
        result = repair.resolve_repository(
            first, cache, verified_policy="strict"
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(result.reason, "multiple_repository_matches")

    def test_repository_miss_has_repository_level_reason(self):
        target = node(file="missing.py", line=10, code="danger(value)")
        cache = FakeCache(
            {(REPO, COMMIT, "missing.py"): "header\n"},
            snapshot=True,
        )
        first = repair.resolve_original_file(
            ref(target), cache, nearby=5, verified_policy="strict"
        )
        result = repair.resolve_repository(
            first, cache, verified_policy="strict"
        )
        self.assertEqual(result.status, "human")
        self.assertEqual(result.reason, "code_not_found_in_repository")


class DescriptionTests(unittest.TestCase):
    def test_chinese_range_anchor_is_updated_but_step_number_is_not(self):
        result, status, conflict = repair.synchronize_desc(
            "第 605–614 行进入处理流程；这是第 1 步。",
            old_file="src/app.py",
            old_span=repair.LineSpan.parse("605-614"),
            new_file="src/app.py",
            new_span=repair.LineSpan.parse("606-614"),
        )
        self.assertEqual(
            result, "第 606-614 行进入处理流程；这是第 1 步。"
        )
        self.assertEqual(status, "updated_location_references")
        self.assertFalse(conflict)

    def test_internal_line_anchor_moves_by_delta(self):
        result, _, _ = repair.synchronize_desc(
            "lines 76-77 perform the write",
            old_file="src/app.py",
            old_span=repair.LineSpan.parse("75-82"),
            new_file="src/app.py",
            new_span=repair.LineSpan.parse("76-82"),
        )
        self.assertEqual(result, "lines 77-78 perform the write")

    def test_file_anchor_is_updated(self):
        result, status, _ = repair.synchronize_desc(
            "See src/old.py:10 and old.py.",
            old_file="src/old.py",
            old_span=repair.LineSpan.parse(10),
            new_file="lib/new.py",
            new_span=repair.LineSpan.parse(12),
        )
        self.assertIn("lib/new.py", result)
        self.assertIn("new.py", result)
        self.assertEqual(status, "updated_location_references")

    def test_semantic_description_without_location_is_unchanged(self):
        desc = "This call performs the dangerous operation."
        result, status, _ = repair.synchronize_desc(
            desc,
            old_file="src/app.py",
            old_span=repair.LineSpan.parse(1),
            new_file="src/app.py",
            new_span=repair.LineSpan.parse(2),
        )
        self.assertEqual(result, desc)
        self.assertEqual(status, "checked_no_location_reference")


class ArtifactTests(unittest.TestCase):
    def test_apply_keeps_integer_representation_and_is_idempotent(self):
        target = node(line=1, code="danger(value)", desc="第 1 行调用")
        rows = [entry(target=target)]
        node_ref = next(repair.iter_nodes(rows))
        match = repair.SourceMatch("src/app.py", 2, 2, "verbatim")
        resolution = repair.Resolution(
            ref=node_ref,
            status="fixed",
            stage="nearby",
            match=match,
            candidates=(match,),
            match_mode="verbatim",
        )
        cache = FakeCache(
            {(REPO, COMMIT, "src/app.py"): "header\ndanger(value)\n"}
        )
        output, diff_rows, human_rows = repair.apply_resolutions(
            rows, [resolution], cache, mode="fix"
        )
        self.assertEqual(output[0]["entry_point"]["line"], 2)
        self.assertEqual(len(diff_rows), 1)
        self.assertFalse(human_rows)
        second_ref = next(repair.iter_nodes(output))
        second = repair.resolve_original_file(
            second_ref, cache, nearby=5, verified_policy="strict"
        )
        self.assertEqual(second.status, "matched")

    def test_check_mode_does_not_apply_fix_candidate(self):
        rows = [entry(target=node(line=1, code="danger(value)"))]
        node_ref = next(repair.iter_nodes(rows))
        match = repair.SourceMatch("src/app.py", 2, 2, "verbatim")
        resolution = repair.Resolution(
            ref=node_ref,
            status="fixed",
            stage="nearby",
            match=match,
            candidates=(match,),
            match_mode="verbatim",
        )
        cache = FakeCache(
            {(REPO, COMMIT, "src/app.py"): "header\ndanger(value)\n"}
        )
        output, diff_rows, _ = repair.apply_resolutions(
            rows, [resolution], cache, mode="check"
        )
        self.assertEqual(output, rows)
        self.assertEqual(len(diff_rows), 1)

    def test_human_review_ids_and_hashes_are_stable(self):
        rows = [entry(target=node(code="danger(value)"))]
        node_ref = next(repair.iter_nodes(rows))
        resolution = repair.Resolution(
            ref=node_ref,
            status="human",
            stage="repository",
            reason="code_not_found_in_repository",
        )
        cache = FakeCache(
            {(REPO, COMMIT, "src/app.py"): "header\n"}
        )
        _, _, first = repair.apply_resolutions(
            rows, [resolution], cache, mode="fix"
        )
        _, _, second = repair.apply_resolutions(
            rows, [resolution], cache, mode="fix"
        )
        self.assertEqual(first, second)
        self.assertTrue(first[0]["review_id"].startswith("loc-"))
        self.assertEqual(len(first[0]["expected_node_sha256"]), 64)

    def test_jsonl_and_csv_outputs_use_lf_and_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            jsonl = base / "rows.jsonl"
            csv_path = base / "rows.csv"
            rows = [entry()]
            repair.write_jsonl(jsonl, rows)
            repair.write_csv(
                csv_path,
                ("entry_id", "code"),
                [{"entry_id": "entry-00001", "code": "一\n二"}],
            )
            first = (jsonl.read_bytes(), csv_path.read_bytes())
            repair.write_jsonl(jsonl, rows)
            repair.write_csv(
                csv_path,
                ("entry_id", "code"),
                [{"entry_id": "entry-00001", "code": "一\n二"}],
            )
            self.assertEqual(first, (jsonl.read_bytes(), csv_path.read_bytes()))
            self.assertNotIn(b"\r", jsonl.read_bytes())
            self.assertNotIn(b"\r", csv_path.read_bytes())
            self.assertTrue(jsonl.read_bytes().endswith(b"\n"))

    def test_offline_snapshot_repository_search(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = repair.HttpSourceCache(root, offline=True)
            snapshot = cache._snapshot_path(REPO, COMMIT)
            source = snapshot / "src" / "actual.py"
            source.parent.mkdir(parents=True)
            source.write_text(
                "header\ndanger(value)\n", encoding="utf-8", newline="\n"
            )
            (snapshot / ".complete").write_text(
                f"{REPO}\n{COMMIT}\n", encoding="utf-8", newline="\n"
            )
            matches = cache.search_repository(
                REPO,
                COMMIT,
                repair.CodePattern(("danger(value)",), "verbatim", False),
            )
            self.assertEqual(
                matches,
                [repair.SourceMatch("src/actual.py", 2, 2, "verbatim")],
            )

    def test_full_baseline_shape(self):
        entries = repair.load_jsonl(ROOT / "data" / "entries.jsonl")
        refs = list(repair.iter_nodes(entries))
        self.assertEqual(len(entries), 408)
        self.assertEqual(len(refs), 2889)
        self.assertEqual(sum(ref.verify == 0 for ref in refs), 107)
        self.assertEqual(
            sum(repair.LineSpan.parse(ref.node["line"]).is_range for ref in refs),
            384,
        )

    def test_dataset_schema_and_report_mapping(self):
        entries = repair.load_jsonl(ROOT / "data" / "entries.jsonl")
        reports = repair.load_jsonl(ROOT / "data" / "reports.jsonl")
        repair.validate_dataset(entries, reports)

    def test_independent_verifier_accepts_complete_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            original_path = base / "entries.jsonl"
            fixed_path = base / "entries.fixed.jsonl"
            reports_path = base / "reports.jsonl"
            diff_path = base / "fix_diff.csv"
            human_path = base / "needs_human.csv"
            sources_path = base / "sources.csv"
            report_json = base / "report.json"
            report_md = base / "report.md"
            cache_dir = base / "cache"

            rows = [
                entry(
                    target=node(
                        line=1,
                        code="danger(value)",
                        desc="第 1 行调用",
                    )
                )
            ]
            repair.write_jsonl(original_path, rows)
            repair.write_jsonl(
                reports_path,
                [{"report_id": "GHSA-AAAA-BBBB-CCCC"}],
            )
            node_ref = next(repair.iter_nodes(rows))
            match = repair.SourceMatch("src/app.py", 2, 2, "verbatim")
            resolution = repair.Resolution(
                ref=node_ref,
                status="fixed",
                stage="nearby",
                match=match,
                candidates=(match,),
                match_mode="verbatim",
            )
            text = "header\ndanger(value)\n"
            fake = FakeCache({(REPO, COMMIT, "src/app.py"): text})
            fixed, diff_rows, human_rows = repair.apply_resolutions(
                rows, [resolution], fake, mode="fix"
            )
            repair.write_jsonl(fixed_path, fixed)
            repair.write_csv(diff_path, repair.DIFF_FIELDS, diff_rows)
            repair.write_csv(human_path, repair.HUMAN_FIELDS, human_rows)
            source_rows = [
                {
                    "repo_url": REPO,
                    "commit": COMMIT,
                    "files_requested": 1,
                    "files_available": 1,
                    "files_missing": 0,
                    "snapshot_required": 0,
                    "snapshot_available": 0,
                    "source_status": "complete",
                }
            ]
            repair.write_csv(sources_path, repair.SOURCE_FIELDS, source_rows)
            cache = repair.HttpSourceCache(cache_dir, offline=True)
            source_path = cache._file_path(
                (REPO, COMMIT, "src/app.py")
            )
            source_path.parent.mkdir(parents=True)
            source_path.write_text(text, encoding="utf-8", newline="\n")
            report = {
                "mode": "fix",
                "verified_policy": "strict",
                "entries": 1,
                "nodes": 2,
                "fix_candidates": 1,
                "changes_applied": 1,
                "needs_human": 0,
                "source_commits": 1,
                "source_commits_complete": 1,
                "input_sha256": repair.file_sha256(original_path),
                "output_sha256": repair.file_sha256(fixed_path),
            }
            repair.write_report_json(report_json, report)
            report_md.write_text("test\n", encoding="utf-8", newline="\n")
            args = SimpleNamespace(
                input=original_path,
                reports=reports_path,
                output=fixed_path,
                diff=diff_path,
                needs_human=human_path,
                source_manifest=sources_path,
                report_json=report_json,
                report_md=report_md,
                cache_dir=cache_dir,
            )
            summary = verify.verify_artifacts(args)
            self.assertEqual(summary["fixes"], 1)


if __name__ == "__main__":
    unittest.main()
