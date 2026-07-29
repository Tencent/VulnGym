from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "entries.jsonl"
SCRIPT = ROOT / "scripts" / "apply_issue7_multistage_chain_patch.py"
VERIFIER = ROOT / "scripts" / "verify_issue7_multistage_outputs.py"
DIFF_PATH = ROOT / "reports" / "issue-7-multistage-chains.diff.csv"
MANUAL_PATH = ROOT / "reports" / "issue-7-multistage-chains.manual_review.csv"
MANIFEST_PATH = ROOT / "reports" / "issue-7-multistage-chain-manifest.json"
REPORT_PATH = ROOT / "reports" / "issue-7-multistage-chain-rebuild.md"

SPEC = importlib.util.spec_from_file_location("issue7_patch", SCRIPT)
issue7_patch = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(issue7_patch)

TARGET_IDS = {
    "entry-00185",
    "entry-00197",
    "entry-00290",
    "entry-00320",
    "entry-00391",
    "entry-00394",
}
MANUAL_IDS = {"entry-00290", "entry-00392", "entry-00395"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MultistageIssue7Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = [
            json.loads(line)
            for line in DATA_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        cls.entry_map = {entry["entry_id"]: entry for entry in cls.entries}

    def test_all_issue_targets_and_extra_tool_sibling_are_rebuilt(self):
        self.assertEqual(issue7_patch.TARGET_IDS, TARGET_IDS)
        self.assertTrue(TARGET_IDS <= set(self.entry_map))
        self.assertEqual(
            {
                entry_id
                for entry_id in TARGET_IDS
                if self.entry_map[entry_id]["verify"] == 1
            },
            TARGET_IDS - {"entry-00290"},
        )

    def test_evidence_matrix_covers_every_target_and_five_direct_fixes(self):
        self.assertEqual(set(issue7_patch.EVIDENCE), TARGET_IDS)
        self.assertEqual(
            len(
                {
                    (item["repo"], item["fix"])
                    for item in issue7_patch.EVIDENCE.values()
                }
            ),
            5,
        )
        for evidence in issue7_patch.EVIDENCE.values():
            self.assertRegex(evidence["vulnerable"], r"^[0-9a-f]{40}$")
            self.assertRegex(evidence["fix"], r"^[0-9a-f]{40}$")
            self.assertTrue(evidence["fix_paths"])
            self.assertTrue(evidence["patch_markers"])

    def test_multistage_and_root_cause_anchors(self):
        expectations = {
            "entry-00185": (
                "getNodeParameter('fileName'",
                "fsWriteFile(resolvedFilePath",
                ("return false",),
            ),
            "entry-00197": (
                "readStringParam(params.args",
                "readFileOverride(mediaUrl)",
                (
                    "resolveSandboxedMediaSource",
                    "sandboxValidated: true",
                    "assertLocalMediaAllowed",
                ),
            ),
            "entry-00290": (
                "execute: async",
                "fileOps.writeFile",
                ("assertNoPathAliasEscape", "resolveSymlinkHopPath"),
            ),
            "entry-00320": (
                "new_filename = file.filename",
                "async_open(str(file_path)",
                ("unique_filename", "folder_path / file_name"),
            ),
            "entry-00391": (
                "def build(",
                "url_path = url_path.replace",
                ("path_params[openapi_name] = value", "urljoin"),
            ),
            "entry-00394": (
                "async def run(",
                "url_path = url_path.replace",
                ("self._director.build", "self._client.send(request)"),
            ),
        }
        for entry_id, (entry_marker, critical_marker, trace_markers) in expectations.items():
            with self.subTest(entry_id=entry_id):
                record = self.entry_map[entry_id]
                self.assertIn(entry_marker, record["entry_point"]["code"])
                self.assertIn(
                    critical_marker,
                    record["critical_operation"]["code"],
                )
                trace_text = "\n".join(
                    node["code"] for node in record["trace"]
                )
                for marker in trace_markers:
                    self.assertIn(marker, trace_text)

    def test_fastmcp_logger_is_removed_and_resource_siblings_are_manual(self):
        trace = "\n".join(
            node["code"] for node in self.entry_map["entry-00391"]["trace"]
        )
        self.assertNotIn("logger.", trace)
        with MANUAL_PATH.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual({row["entry_id"] for row in rows}, MANUAL_IDS)
        for row in rows:
            self.assertTrue(row["blocker"])
            self.assertTrue(row["fix_evidence"])
            self.assertTrue(row["candidate_action"])

    def test_entry_00290_is_an_explicit_test_only_confidence_boundary(self):
        self.assertEqual(self.entry_map["entry-00290"]["verify"], 0)
        evidence = issue7_patch.EVIDENCE["entry-00290"]
        self.assertTrue(evidence["tests_only"])
        self.assertTrue(
            all(path.endswith(".test.ts") for path in evidence["fix_paths"])
        )
        manual_text = MANUAL_PATH.read_text(encoding="utf-8")
        self.assertIn("modifies only two test files", manual_text)

    def test_diff_is_complete_replayable_and_nonempty(self):
        with DIFF_PATH.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 22)
        self.assertEqual(
            Counter(row["entry_id"] for row in rows),
            {
                "entry-00185": 4,
                "entry-00197": 4,
                "entry-00290": 3,
                "entry-00320": 4,
                "entry-00391": 4,
                "entry-00394": 3,
            },
        )
        for row in rows:
            self.assertNotEqual(json.loads(row["before"]), json.loads(row["after"]))
            self.assertEqual(
                self.entry_map[row["entry_id"]][row["field"]],
                json.loads(row["after"]),
            )
            self.assertTrue(row["reason"])

    def test_manifest_hashes_and_counts_match_artifacts(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["dataset_sha256"], digest(DATA_PATH))
        self.assertEqual(manifest["diff_sha256"], digest(DIFF_PATH))
        self.assertEqual(
            manifest["manual_review_sha256"],
            digest(MANUAL_PATH),
        )
        self.assertEqual(manifest["target_ids"], sorted(TARGET_IDS))
        self.assertEqual(manifest["manual_review_ids"], sorted(MANUAL_IDS))
        self.assertEqual(manifest["node_occurrences"], 52)
        self.assertEqual(manifest["diff_rows"], 22)

    def test_generator_is_idempotent(self):
        paths = (DATA_PATH, DIFF_PATH, MANUAL_PATH, MANIFEST_PATH)
        before = {path: digest(path) for path in paths}
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, {path: digest(path) for path in paths})

    def test_independent_verifier_accepts_committed_outputs(self):
        result = subprocess.run(
            [sys.executable, str(VERIFIER)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("6 rebuilt targets, 52 nodes", result.stdout)

    def test_documented_audit_statistics_match_dataset(self):
        verified = [entry for entry in self.entries if entry["verify"] == 1]
        grouped = defaultdict(list)
        for entry in self.entries:
            grouped[entry["report_id"]].append(entry)
        full = sum(
            all(entry["verify"] == 1 for entry in group)
            for group in grouped.values()
        )
        partial = sum(
            any(entry["verify"] == 1 for entry in group)
            and any(entry["verify"] == 0 for entry in group)
            for group in grouped.values()
        )
        self.assertEqual((len(verified), full, partial), (397, 178, 0))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        readme_zh = (ROOT / "README_zh.md").read_text(encoding="utf-8")
        self.assertIn("397 / 408 (97.3 %)", readme)
        self.assertIn("**178** have all", readme)
        self.assertIn("**0** are partially", readme)
        self.assertIn("397 / 408 (97.3%)", readme_zh)

    def test_report_explains_external_prerequisites_and_runtime_order(self):
        report = REPORT_PATH.read_text(encoding="utf-8")
        for marker in (
            "external prerequisite",
            "two-stage TOCTOU",
            "Source definition order",
            "test-only",
            "direct children",
            "52 annotated node occurrences",
            "22 field-level changes",
        ):
            self.assertIn(marker, report)

    def test_text_artifacts_are_utf8_lf_with_one_final_newline(self):
        for path in (
            DIFF_PATH,
            MANUAL_PATH,
            MANIFEST_PATH,
            REPORT_PATH,
            SCRIPT,
            VERIFIER,
        ):
            data = path.read_bytes()
            data.decode("utf-8")
            self.assertNotIn(b"\r", data, path)
            self.assertTrue(data.endswith(b"\n"), path)
            self.assertFalse(data.endswith(b"\n\n"), path)


if __name__ == "__main__":
    unittest.main()
