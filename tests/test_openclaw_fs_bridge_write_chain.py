from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fs_bridge_chain",
    ROOT / "scripts" / "rebuild_openclaw_fs_bridge_write_chain.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OpenClawFsBridgeWriteChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = MODULE.load_jsonl(ROOT / "data" / "entries.jsonl")
        cls.by_id = {entry["entry_id"]: entry for entry in cls.entries}

    def test_canonical_target_payloads_match_the_rebuild(self) -> None:
        for entry_id, patch in MODULE.TARGET_PATCHES.items():
            entry = self.by_id[entry_id]
            self.assertEqual(entry["report_id"], MODULE.REPORT_ID)
            self.assertEqual(entry["commit"], MODULE.VULNERABLE_COMMIT)
            for field in MODULE.PATCH_FIELDS:
                self.assertEqual(entry[field], patch[field])

    def test_two_distinct_ingress_paths_share_the_real_write_sink(self) -> None:
        write_tool = self.by_id["entry-00301"]
        apply_patch = self.by_id["entry-00302"]
        self.assertEqual(write_tool["entry_point"]["file"], "src/agents/pi-tools.read.ts")
        self.assertEqual(apply_patch["entry_point"]["file"], "src/agents/apply-patch.ts")
        self.assertEqual(write_tool["critical_operation"], apply_patch["critical_operation"])
        self.assertIn("mktemp", write_tool["critical_operation"]["code"])
        self.assertIn('cat >"$tmp"', write_tool["critical_operation"]["code"])

    def test_traces_show_check_stage_write_and_late_commit_guard(self) -> None:
        for entry_id in MODULE.TARGET_IDS:
            trace_code = [item["code"] for item in self.by_id[entry_id]["trace"]]
            check_index = next(i for i, code in enumerate(trace_code) if "assertPathSafety" in code)
            write_index = next(i for i, code in enumerate(trace_code) if "mktemp" in code)
            commit_index = next(i for i, code in enumerate(trace_code) if "buildWriteCommitPlan" in code)
            plan_index = next(i for i, code in enumerate(trace_code) if "recheckBeforeCommand" in code)
            self.assertLess(check_index, write_index)
            self.assertLess(write_index, commit_index)
            self.assertLess(commit_index, plan_index)

    def test_unrelated_stat_and_abort_signal_claims_are_removed(self) -> None:
        for entry_id in MODULE.TARGET_IDS:
            entry = self.by_id[entry_id]
            serialized = str(
                {
                    "entry_point": entry["entry_point"],
                    "critical_operation": entry["critical_operation"],
                    "trace": entry["trace"],
                }
            )
            self.assertNotIn("buildStatPlan", serialized)
            self.assertNotIn("readFile 方法的闭合括号", serialized)
            self.assertNotIn("AbortSignal 干预", serialized)

    def test_dataset_counts_and_report_join_remain_consistent(self) -> None:
        reports = MODULE.load_jsonl(ROOT / "data" / "reports.jsonl")
        report = next(item for item in reports if item["report_id"] == MODULE.REPORT_ID)
        self.assertEqual(report["entry_ids"], list(MODULE.TARGET_IDS))
        self.assertEqual(report["commit"], MODULE.VULNERABLE_COMMIT)
        self.assertEqual(len(self.entries), 408)
        self.assertEqual(len(reports), 184)
        self.assertEqual(sum(entry["verify"] == 1 for entry in self.entries), 391)
        self.assertEqual(len({entry["report_id"] for entry in self.entries if entry["verify"] == 1}), 177)

    def test_diff_artifact_replays_baseline_to_canonical_data(self) -> None:
        MODULE.check_diff_artifact(self.entries)
        patched, rows = MODULE.patch_entries(self.entries)
        self.assertEqual(patched, self.entries)
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
