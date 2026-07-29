from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trace_cleanup.py"
VERIFIER = ROOT / "scripts" / "verify_trace_cleanup_outputs.py"
SPEC = importlib.util.spec_from_file_location("trace_cleanup", SCRIPT)
trace_cleanup = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = trace_cleanup
SPEC.loader.exec_module(trace_cleanup)


def node(
    line: int | str,
    *,
    file: str = "a.py",
    code: str | None = None,
    desc: str = "node",
) -> dict:
    return {
        "file": file,
        "line": line,
        "code": code or f"line {line}",
        "desc": desc,
    }


def entry(
    *,
    entry_id: str = "entry-90000",
    verify: int = 0,
    entry_line: int | str = 10,
    critical_line: int | str = 20,
    trace: list[dict] | None = None,
) -> dict:
    return {
        "commit": "a" * 40,
        "critical_operation": node(critical_line),
        "entry_id": entry_id,
        "entry_point": node(entry_line),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "example",
        "repo_url": "https://github.com/example/example",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "trace": trace or [],
        "verify": verify,
        "vuln_category_l1": "test",
        "vuln_category_l2": "test",
        "vuln_ids": ["GHSA-AAAA-BBBB-CCCC"],
        "vuln_title": "test",
    }


class SpanTests(unittest.TestCase):
    def test_integer_line(self):
        self.assertEqual(trace_cleanup.Span.parse(7), trace_cleanup.Span(7, 7))

    def test_range_line(self):
        self.assertEqual(
            trace_cleanup.Span.parse("7-11"),
            trace_cleanup.Span(7, 11),
        )

    def test_invalid_lines_are_rejected(self):
        for value in (0, -1, True, "0-1", "5-4", "5", "a-b"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    trace_cleanup.Span.parse(value)


class PolicyTests(unittest.TestCase):
    def test_exact_duplicate_with_same_desc_is_removed_in_fix_mode(self):
        duplicate = node(12, code="same", desc="same")
        sample = entry(trace=[duplicate, dict(duplicate)])
        result = trace_cleanup.analyze_entries([sample], mode="fix")
        self.assertEqual(len(result.entries[0]["trace"]), 1)
        self.assertEqual(result.findings[0].kind, "duplicate")
        self.assertEqual(result.findings[0].action, "remove")
        self.assertEqual(result.stats["changes_applied"], 1)

    def test_duplicate_with_conflicting_desc_requires_review(self):
        sample = entry(
            trace=[
                node(12, code="same", desc="first"),
                node(12, code="same", desc="second"),
            ]
        )
        result = trace_cleanup.analyze_entries([sample], mode="fix")
        self.assertEqual(len(result.entries[0]["trace"]), 2)
        self.assertEqual(result.findings[0].action, "manual_review")

    def test_duplicate_detection_preserves_line_representation(self):
        sample = entry(
            trace=[
                node(12, code="same"),
                node("12-12", code="same"),
            ]
        )
        result = trace_cleanup.analyze_entries([sample], mode="fix")
        self.assertFalse(
            any(finding.kind == "duplicate" for finding in result.findings)
        )

    def test_verified_duplicate_is_protected(self):
        duplicate = node(12, code="same", desc="same")
        sample = entry(verify=1, trace=[duplicate, dict(duplicate)])
        result = trace_cleanup.analyze_entries([sample], mode="fix")
        self.assertEqual(len(result.entries[0]["trace"]), 2)
        self.assertEqual(result.findings[0].action, "protected_verified")

    def test_before_and_after_findings_are_detected(self):
        sample = entry(trace=[node(5), node(25)])
        result = trace_cleanup.analyze_entries([sample])
        self.assertEqual(
            [finding.kind for finding in result.findings],
            ["before_entry", "after_critical"],
        )

    def test_review_policy_does_not_delete_order_findings(self):
        sample = entry(trace=[node(5), node(25)])
        result = trace_cleanup.analyze_entries(
            [sample], mode="fix", order_policy="review"
        )
        self.assertEqual(len(result.entries[0]["trace"]), 2)
        self.assertEqual(
            {finding.action for finding in result.findings},
            {"manual_review"},
        )

    def test_structural_policy_deletes_unreviewed_order_findings(self):
        sample = entry(trace=[node(5), node(25)])
        result = trace_cleanup.analyze_entries(
            [sample], mode="fix", order_policy="structural"
        )
        self.assertEqual(result.entries[0]["trace"], [])
        self.assertEqual(result.stats["changes_applied"], 2)

    def test_reviewed_exception_survives_structural_policy(self):
        canonical = json.loads(
            next(
                line
                for line in (ROOT / "data" / "entries.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if '"entry_id": "entry-00103"' in line
            )
        )
        result = trace_cleanup.analyze_entries(
            [canonical], mode="fix", order_policy="structural"
        )
        finding = next(
            finding
            for finding in result.findings
            if finding.kind == "before_entry"
        )
        self.assertEqual(finding.action, "manual_review")
        self.assertEqual(
            result.entries[0]["trace"],
            canonical["trace"],
        )

    def test_overlapping_ranges_are_not_out_of_bounds(self):
        sample = entry(
            entry_line="10-12",
            critical_line="20-22",
            trace=[node("9-10"), node("22-23")],
        )
        result = trace_cleanup.analyze_entries([sample])
        self.assertEqual(result.findings, [])

    def test_cross_file_nodes_are_never_compared_or_reordered(self):
        cross = node(1, file="other.py")
        sample = entry(trace=[cross, node(15)])
        result = trace_cleanup.analyze_entries(
            [sample], mode="fix", order_policy="structural"
        )
        self.assertEqual(result.entries[0]["trace"], [cross, node(15)])
        self.assertEqual(result.stats["cross_file_comparisons_skipped"], 2)

    def test_trace_node_matching_anchors_is_not_an_internal_duplicate(self):
        sample = entry(trace=[node(10), node(20)])
        result = trace_cleanup.analyze_entries([sample], mode="fix")
        self.assertFalse(
            any(finding.kind == "duplicate" for finding in result.findings)
        )

    def test_fix_mode_is_idempotent(self):
        duplicate = node(12, code="same", desc="same")
        sample = entry(trace=[duplicate, dict(duplicate)])
        first = trace_cleanup.analyze_entries([sample], mode="fix")
        second = trace_cleanup.analyze_entries(first.entries, mode="fix")
        self.assertEqual(first.entries, second.entries)
        self.assertEqual(second.stats["changes_applied"], 0)


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input_text, cls.entries = trace_cleanup.load_jsonl(
            ROOT / "data" / "entries.jsonl"
        )
        _, cls.reports = trace_cleanup.load_jsonl(
            ROOT / "data" / "reports.jsonl"
        )
        cls.result = trace_cleanup.analyze_entries(
            cls.entries,
            mode="fix",
            order_policy="review",
        )

    def test_full_dataset_counts_match_the_audited_baseline(self):
        stats = self.result.stats
        self.assertEqual(stats["entries_scanned"], 408)
        self.assertEqual(stats["trace_nodes_scanned"], 2073)
        self.assertEqual(
            stats["finding_counts"],
            {
                "after_critical": 237,
                "before_entry": 139,
                "duplicate": 7,
            },
        )
        self.assertEqual(stats["cross_file_comparisons_skipped"], 1658)

    def test_default_fix_is_conservative_and_byte_stable(self):
        self.assertEqual(self.result.stats["changes_applied"], 0)
        self.assertEqual(
            trace_cleanup._serialize_jsonl(self.result.entries),
            self.input_text,
        )

    def test_only_four_unverified_entries_require_manual_review(self):
        unverified = {
            finding.entry_id
            for finding in self.result.findings
            if finding.action == "manual_review"
        }
        self.assertEqual(unverified, trace_cleanup.TARGET_REVIEW_IDS)
        self.assertEqual(
            self.result.stats["action_counts"],
            {"manual_review": 4, "protected_verified": 379},
        )

    def test_all_duplicate_candidates_have_conflicting_descriptions(self):
        duplicates = [
            finding
            for finding in self.result.findings
            if finding.kind == "duplicate"
        ]
        self.assertEqual(len(duplicates), 7)
        self.assertTrue(
            all(finding.action == "protected_verified" for finding in duplicates)
        )

    def test_dataset_and_report_mapping_remain_valid(self):
        trace_cleanup.validate_dataset(self.result.entries, self.reports)

    def test_generated_artifacts_have_lf_and_expected_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            paths = {
                "output_path": base / "fixed.jsonl",
                "findings_path": base / "findings.csv",
                "diff_path": base / "diff.csv",
                "needs_human_path": base / "human.csv",
                "report_json_path": base / "report.json",
                "report_md_path": base / "report.md",
            }
            trace_cleanup.write_artifacts(
                self.input_text,
                self.result,
                **paths,
            )
            self.assertNotIn(b"\r\n", paths["findings_path"].read_bytes())
            with paths["findings_path"].open(
                encoding="utf-8", newline=""
            ) as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 383)
            with paths["diff_path"].open(
                encoding="utf-8", newline=""
            ) as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 0)
            with paths["needs_human_path"].open(
                encoding="utf-8", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 4)
            self.assertEqual(
                {row["entry_id"] for row in rows},
                trace_cleanup.TARGET_REVIEW_IDS,
            )
            for row in rows:
                for field in (
                    "review_id",
                    "dataset_sha256",
                    "entry_sha256",
                    "node_sha256",
                    "anchor_sha256",
                ):
                    self.assertRegex(row[field], r"^[0-9a-f]{64}$")
                self.assertEqual(row["decision"], "")
                self.assertEqual(row["reviewer"], "")
                self.assertEqual(row["rationale"], "")

    def test_committed_fixed_artifact_matches_canonical_bytes(self):
        fixed = ROOT / "data" / "entries.trace_fixed.jsonl"
        self.assertEqual(fixed.read_bytes(), (ROOT / "data" / "entries.jsonl").read_bytes())

    def test_report_records_hash_equality_and_zero_changes(self):
        report = json.loads(
            (ROOT / "reports" / "trace_structure_report.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(report["input_sha256"], report["output_sha256"])
        self.assertEqual(report["changes_applied"], 0)
        self.assertEqual(report["manual_review_rows"], 4)
        self.assertEqual(report["manual_review_schema_version"], 1)
        self.assertRegex(
            report["manual_review_manifest_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(
            report["needs_human_entries"],
            sorted(trace_cleanup.TARGET_REVIEW_IDS),
        )

    def test_documentation_records_the_semantic_safety_boundary(self):
        readme = (ROOT / "scripts" / "README_trace_cleanup.md").read_text(
            encoding="utf-8"
        )
        for term in (
            "源码定义顺序不等于运行时顺序",
            "--order-policy structural",
            "entry-00185",
            "trace_needs_human.csv",
        ):
            self.assertIn(term, readme)

    def test_acceptance_matrix_covers_issue_outputs_and_safety_policy(self):
        matrix = (
            ROOT / "reports" / "trace_cleanup_acceptance_matrix.md"
        ).read_text(encoding="utf-8")
        for term in (
            "整数和范围行号",
            "不误排跨文件调用链",
            "不排序；跳过并汇总记录",
            "trace_fix_diff.csv",
            "trace_needs_human.csv",
            "零自动修改",
            "防过期人工决策",
            "独立产物验证",
        ):
            self.assertIn(term, matrix)

    def _run_verifier(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VERIFIER), *args],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    @staticmethod
    def _write_review_csv(
        path: Path,
        fieldnames: list[str],
        rows: list[dict[str, str]],
    ) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames,
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)

    def test_independent_verifier_accepts_committed_artifacts(self):
        result = self._run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "4 fingerprinted manual reviews",
            result.stdout,
        )

    def test_independent_verifier_rejects_stale_review_fingerprints(self):
        review_path = ROOT / "reports" / "trace_needs_human.csv"
        with review_path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            original_rows = list(reader)

        for field in (
            "dataset_sha256",
            "entry_sha256",
            "node_sha256",
            "anchor_sha256",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                rows = [dict(row) for row in original_rows]
                rows[0][field] = "0" * 64
                decisions = Path(temp) / "decisions.csv"
                self._write_review_csv(decisions, fieldnames, rows)
                result = self._run_verifier("--decisions", str(decisions))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"stale {field}", result.stderr)

    def test_manual_decision_requires_allowed_value_reviewer_and_rationale(self):
        review_path = ROOT / "reports" / "trace_needs_human.csv"
        with review_path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            original_rows = list(reader)

        cases = (
            ("delete", "", "", "invalid decision"),
            ("keep", "", "", "requires reviewer and rationale"),
            ("", "reviewer", "reason", "require a decision"),
        )
        for decision, reviewer, rationale, message in cases:
            with (
                self.subTest(decision=decision, reviewer=reviewer),
                tempfile.TemporaryDirectory() as temp,
            ):
                rows = [dict(row) for row in original_rows]
                rows[0]["decision"] = decision
                rows[0]["reviewer"] = reviewer
                rows[0]["rationale"] = rationale
                decisions = Path(temp) / "decisions.csv"
                self._write_review_csv(decisions, fieldnames, rows)
                result = self._run_verifier("--decisions", str(decisions))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

        with tempfile.TemporaryDirectory() as temp:
            rows = [dict(row) for row in original_rows]
            rows[0]["decision"] = "keep"
            rows[0]["reviewer"] = "maintainer"
            rows[0]["rationale"] = "Runtime call order confirms this node."
            decisions = Path(temp) / "decisions.csv"
            self._write_review_csv(decisions, fieldnames, rows)
            result = self._run_verifier("--decisions", str(decisions))
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
