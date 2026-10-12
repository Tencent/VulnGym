#!/usr/bin/env python3
"""Validate n8n semantic fix entries against SCHEMA.md and acceptance criteria.

Run from repo root:
    python scripts/validate_n8n_fix.py
"""
from __future__ import annotations

import json
import re
import sys
import io
from collections import defaultdict
from pathlib import Path

# Fix stdout encoding on Windows (GBK console)
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ROOT / "data" / "entries.fixed.jsonl"
REPORTS = ROOT / "data" / "reports.jsonl"

TARGET_IDS = {
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00511",
    "entry-00512",
}

TOP_KEYS_REQUIRED = {
    "entry_id", "report_id", "source_link", "vuln_ids", "origin",
    "project", "repo_url", "commit", "vuln_title",
    "vuln_category_l1", "vuln_category_l2",
    "entry_point", "critical_operation", "trace", "verify",
}

NODE_KEYS_REQUIRED = {"file", "line", "code"}
NODE_KEYS_OPTIONAL = {"desc"}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  [FAIL] {path}:{i}: invalid JSON: {e}")
                return []
    return rows


def validate_line_value(line_val, node_path: str) -> bool:
    if isinstance(line_val, int):
        if line_val < 1:
            print(f"  [FAIL] {node_path}: line {line_val} < 1 (not permitted)")
            return False
        return True
    if isinstance(line_val, str):
        if not re.fullmatch(r"\d+-\d+", line_val):
            print(f"  [FAIL] {node_path}: line range '{line_val}' doesn't match 'int-int'")
            return False
        parts = line_val.split("-")
        a, b = int(parts[0]), int(parts[1])
        if a < 1:
            print(f"  [FAIL] {node_path}: line range start {a} < 1")
            return False
        if a > b:
            print(f"  [FAIL] {node_path}: line range start {a} > end {b}")
            return False
        return True
    print(f"  [FAIL] {node_path}: line is not int or range string")
    return False


def validate_node(node: dict, node_path: str) -> bool:
    if not isinstance(node, dict):
        print(f"  [FAIL] {node_path}: node is not a dict")
        return False
    ok = True
    for key in NODE_KEYS_REQUIRED:
        if key not in node:
            print(f"  [FAIL] {node_path}: missing required key '{key}'")
            ok = False
    for key in node:
        if key not in NODE_KEYS_REQUIRED and key not in NODE_KEYS_OPTIONAL:
            print(f"  [FAIL] {node_path}: unexpected key '{key}'")
            ok = False
    if "line" in node and not validate_line_value(node["line"], node_path):
        ok = False
    return ok


def validate_entry(row: dict) -> list[str]:
    errors = []
    entry_id = row.get("entry_id", "<unknown>")

    for key in TOP_KEYS_REQUIRED:
        if key not in row:
            errors.append(f"{entry_id}: missing top-level key '{key}'")

    if "verify" in row and row["verify"] not in (0, 1):
        errors.append(f"{entry_id}: verify is not 0 or 1, got {row['verify']}")

    # Commit: 40 hex chars (allow mixed case - pre-existing in baseline)
    commit = row.get("commit", "")
    if commit:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            errors.append(f"{entry_id}: commit '{commit}' is not 40 hex chars")

    # repo_url
    url = row.get("repo_url", "")
    if url and not url.startswith("https://github.com/"):
        errors.append(f"{entry_id}: repo_url doesn't start with https://github.com/")

    # source_link contains github.com/advisories/
    slink = row.get("source_link", "")
    rid = row.get("report_id", "")
    if slink and "github.com/advisories/" not in slink:
        errors.append(f"{entry_id}: source_link doesn't contain github.com/advisories/")
    if slink and rid:
        m = re.search(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", slink, re.IGNORECASE)
        if m and m.group(0).upper() != rid:
            errors.append(f"{entry_id}: source_link GHSA mismatch")

    if "entry_point" in row and not validate_node(row["entry_point"], f"{entry_id}/entry_point"):
        errors.append(f"{entry_id}: entry_point validation failed")

    if "critical_operation" in row and not validate_node(row["critical_operation"], f"{entry_id}/critical_operation"):
        errors.append(f"{entry_id}: critical_operation validation failed")

    if "trace" in row:
        if not isinstance(row["trace"], list):
            errors.append(f"{entry_id}: trace is not an array")
        else:
            for i, node in enumerate(row["trace"]):
                if not validate_node(node, f"{entry_id}/trace[{i}]"):
                    errors.append(f"{entry_id}: trace[{i}] validation failed")

    INTERNAL = {"description", "human_remark", "pipeline_id", "annotated_by",
                "is_active", "created_at", "generality", "detection_type",
                "ground_truth", "taint_source", "taint_sink", "vuln_category_l3"}
    for key in INTERNAL:
        if key in row:
            errors.append(f"{entry_id}: contains internal field '{key}'")

    return errors


def check_semantic_correctness(target_entries: dict) -> tuple[int, int]:
    """Check critical_operation points to vulnerable code. Returns (passed, total).

    NOTE: This only validates that critical_operation fields match expected patterns.
    True semantic validation requires human review of:
    - Whether the file/line actually corresponds to the vulnerability trigger point
    - Whether the trace nodes form a coherent call/data flow
    - Whether the fix aligns with the advisory and patch analysis
    """
    expected_cos = {
        "entry-00099": {
            "file": "packages/workflow/src/expression-evaluator-proxy.ts",
            "patterns": ["Tournament", "PrototypeSanitizer"],
        },
        "entry-00100": {
            "file": "packages/workflow/src/expression-evaluator-proxy.ts",
            "patterns": ["Tournament", "PrototypeSanitizer"],
        },
        "entry-00103": {
            "file": "packages/core/src/html-sandbox.ts",
            "patterns": ["contentTypeLower", "startsWith", "toLowerCase"],
        },
        "entry-00176": {
            "file": "packages/@n8n/task-runner-python/src/task_analyzer.py",
            "patterns": ["BLOCKED_ATTRIBUTES", "node.attr"],
        },
        "entry-00511": {
            "file": "packages/@n8n/expression-runtime/src/extensions/extend.ts",
            "patterns": ["inputAny", "functionName"],
        },
        "entry-00512": {
            "file": "packages/@n8n/expression-runtime/src/runtime/reset.ts",
            "patterns": ["__sanitize", "__data"],
        },
    }

    sem_correct = 0
    for tid, expected in sorted(expected_cos.items()):
        entry = target_entries.get(tid)
        if not entry:
            print(f"  [FAIL] {tid}: not found in target entries")
            continue
        co = entry.get("critical_operation", {})
        co_file = co.get("file", "")
        co_code = co.get("code", "")
        co_desc = co.get("desc", "")
        co_text = co_code + co_desc  # search across code + desc

        file_ok = expected["file"] in co_file
        pattern_ok = all(p in co_text for p in expected["patterns"])

        if file_ok and pattern_ok:
            print(f"  [OK] {tid}: critical_operation -> {expected['file']}")
            for pat in expected["patterns"]:
                print(f"      pattern '{pat}': found")
            sem_correct += 1
        else:
            print(f"  [FAIL] {tid}: mismatch")
            print(f"    expected file: {expected['file']}")
            print(f"    actual file:   {co_file}")
            for pat in expected["patterns"]:
                status = "FOUND" if pat in co_text else "MISSING"
                print(f"    pattern '{pat}': {status}")

    return sem_correct, len(expected_cos)


def check_entry_point_external_input(target_entries: dict) -> int:
    """Check entry_point desc captures how external input enters. Returns (passed, total).

    NOTE: This only checks for keyword presence in desc, not actual data flow.
    True validation requires verifying that entry_point truly represents the
    entry where external input enters the vulnerability chain.
    """
    keywords = [
        "用户", "输入", "请求", "参数", "配置", "工作流", "节点",
        "external", "input", "user", "request", "parameter", "config",
        "workflow", "node", "expression",
    ]
    ok = 0
    for tid in sorted(TARGET_IDS):
        entry = target_entries.get(tid)
        if not entry:
            continue
        desc = entry.get("entry_point", {}).get("desc", "")
        if any(kw.lower() in desc.lower() for kw in keywords):
            print(f"  [OK] {tid}: entry_point desc captures external input")
            ok += 1
        else:
            print(f"  [WARN] {tid}: entry_point desc may not show external input path")
            print(f"    {desc[:80]}...")
    return ok


def main() -> int:
    print("=" * 60)
    print("VulnGym n8n Semantic Fix Validation")
    print("=" * 60)
    print()

    # 1. Load data
    print("[1] Loading data files...")
    entries = load_jsonl(ENTRIES)
    reports = load_jsonl(REPORTS)
    if not entries or not reports:
        return 1
    print(f"  [OK] entries.fixed.jsonl: {len(entries)} rows")
    print(f"  [OK] reports.jsonl: {len(reports)} rows")

    # 2. Row counts
    print()
    print("[2] Checking row counts...")
    row_ok = len(entries) == 408 and len(reports) == 184
    print(f"  entries.fixed.jsonl: {'OK' if len(entries) == 408 else 'FAIL'} ({len(entries)} rows)")
    print(f"  reports.jsonl: {'OK' if len(reports) == 184 else 'FAIL'} ({len(reports)} rows)")

    # 3. Join consistency
    print()
    print("[3] Checking report_id <-> entry_id join...")
    report_ids = {r["report_id"] for r in reports}
    orphan = [e for e in entries if e.get("report_id") not in report_ids]
    if orphan:
        print(f"  [FAIL] {len(orphan)} entries have orphaned report_id")
    else:
        print(f"  [OK] All entries have valid report_id")

    # 4. report.entry_ids consistency
    print()
    print("[4] Checking report.entry_ids consistency...")
    mm = 0
    for r in reports:
        exp = sorted(r.get("entry_ids", []))
        act = sorted(e["entry_id"] for e in entries if e.get("report_id") == r["report_id"])
        if exp != act:
            mm += 1
            print(f"  [FAIL] {r['report_id']}: {exp} vs {act}")
    if mm == 0:
        print(f"  [OK] All reports have matching entry_ids")

    # 5. SCHEMA constraints
    print()
    print("[5] Validating SCHEMA.md constraints on all 408 entries...")
    all_errors = []
    for entry in entries:
        all_errors.extend(validate_entry(entry))
    if all_errors:
        print(f"  [FAIL] {len(all_errors)} schema errors:")
        for err in all_errors[:10]:
            print(f"    - {err}")
        if len(all_errors) > 10:
            print(f"    ... and {len(all_errors) - 10} more")
    else:
        print(f"  [OK] All 408 entries pass SCHEMA.md validation")

    # 6. Target entries
    print()
    print("[6] Target entry details...")
    target_entries = {e["entry_id"]: e for e in entries if e["entry_id"] in TARGET_IDS}
    found = len(target_entries)
    print(f"  Found: {found}/{len(TARGET_IDS)}")
    for tid in sorted(TARGET_IDS):
        e = target_entries.get(tid)
        if not e:
            print(f"  [FAIL] {tid}: NOT FOUND")
            continue
        print(f"\n  [{tid}]")
        print(f"    commit:    {e.get('commit', 'N/A')}")
        print(f"    report:    {e.get('report_id', 'N/A')}")
        print(f"    verify:    {e.get('verify', 'N/A')}")
        ep = e.get("entry_point", {})
        co = e.get("critical_operation", {})
        print(f"    ep:        {ep.get('file', '?')}:{ep.get('line', '?')}")
        print(f"    co:        {co.get('file', '?')}:{co.get('line', '?')}")
        checks = [
            ("verify=1", e.get("verify") == 1),
            ("ep has desc", bool(ep.get("desc"))),
            ("co has desc", bool(co.get("desc"))),
            ("ep!=co", not (ep.get("file") == co.get("file") and ep.get("line") == co.get("line"))),
        ]
        for name, ok in checks:
            print(f"    {'[OK]' if ok else '[FAIL]'} {name}")

    # 7. Semantic correctness of critical_operation
    print()
    print("[7] Semantic correctness: critical_operation -> vulnerable code...")
    print("  NOTE: This only validates field patterns, not actual semantic correctness.")
    print("  True semantic validation requires human review against advisory + source code.")
    sem_correct, sem_total = check_semantic_correctness(target_entries)

    # 8. Entry_point external input
    print()
    print("[8] Entry_point external input capture...")
    print("  NOTE: This only checks keyword presence, not actual data flow.")
    ep_ok = check_entry_point_external_input(target_entries)

    # Summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    checks = [
        ("Row counts (408 entries, 184 reports)", row_ok),
        ("SCHEMA.md invariants", len(all_errors) == 0),
        ("All 6 target entries found", found == len(TARGET_IDS)),
        ("All 6 entries have verify=1",
         all(target_entries.get(tid, {}).get("verify") == 1 for tid in TARGET_IDS)),
        ("Join consistency", len(orphan) == 0 and mm == 0),
        ("Semantic field patterns match expected", sem_correct == sem_total),
        ("Entry_point desc contains external input keywords", ep_ok == len(TARGET_IDS)),
    ]

    all_pass = True
    for name, passed in checks:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
        if not passed:
            all_pass = False

    print()
    print("-" * 60)
    print("IMPORTANT DISCLAIMER:")
    print("  Automated checks validate SCHEMA compliance and field patterns only.")
    print("  True semantic validation requires human expert review to confirm:")
    print("  - entry_point correctly identifies where external input enters")
    print("  - critical_operation points to the actual vulnerability trigger")
    print("  - trace nodes form a coherent vulnerability chain")
    print("  - fixes align with advisory + patch analysis")
    print("  See n8n_semantic_fix_notes.md for human-reviewed justification.")
    print("-" * 60)
    print()
    if all_pass:
        print("AUTOMATED CHECKS PASSED")
        print("Human review of semantic correctness is still required.")
        return 0
    else:
        print("SOME AUTOMATED CHECKS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
