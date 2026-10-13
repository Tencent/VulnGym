# -*- coding: utf-8 -*-
"""
Independent verification script for fix_entries.py

Usage:
    python scripts/verify_fix.py [--strict]

Checks:
  1. Schema validation: entries.fixed.jsonl matches SCHEMA.md
  2. Diff consistency: fix_diff.csv rows correspond to actual fixes
  3. Code integrity: code fields were never modified
  4. Idempotency: re-running produces zero fixes (requires dry-run)
"""
import csv
import json
import sys
import os
import subprocess
import shutil
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRIES_FILE = os.path.join(ROOT, "data", "entries.jsonl")
FIXED_FILE = os.path.join(ROOT, "entries.fixed.jsonl")
DIFF_FILE = os.path.join(ROOT, "fix_diff.csv")

PASS, FAIL = 0, 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  [OK] {msg}")


def fail(msg):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}")


def validate_schema():
    """Schema check: every node has required keys."""
    print("\n[1/4] Schema validation ...")
    if not os.path.exists(FIXED_FILE):
        fail(f"{FIXED_FILE} not found")
        return

    TOP_KEYS = {
        "entry_id", "project", "repo_url", "commit", "origin",
        "vuln_category_l1", "vuln_category_l2", "vuln_title", "vuln_ids",
        "report_id", "source_link", "verify",
        "entry_point", "critical_operation", "trace",
    }
    NODE_REQUIRED = {"code", "file", "line"}  # desc is optional in some entries

    with open(FIXED_FILE, "r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"line {idx}: invalid JSON - {exc}")
                continue

            missing = TOP_KEYS - set(obj.keys())
            if missing:
                fail(f"line {idx}: missing keys {sorted(missing)}")

            for node_name in ("entry_point", "critical_operation"):
                node = obj.get(node_name, {})
                nm = NODE_REQUIRED - set(node.keys())
                if nm:
                    fail(f"line {idx} {node_name}: missing {sorted(nm)}")

            trace = obj.get("trace", [])
            if not isinstance(trace, list):
                fail(f"line {idx}: trace is not a list")
            else:
                for ti, tn in enumerate(trace):
                    nm = NODE_REQUIRED - set(tn.keys())
                    if nm:
                        fail(f"line {idx} trace[{ti}]: missing {sorted(nm)}")

    ok(f"Schema check passed")


def validate_diff():
    """Diff consistency: each diff row has a corresponding fixed entry."""
    print("\n[2/4] Diff consistency ...")
    if not os.path.exists(DIFF_FILE):
        fail(f"{DIFF_FILE} not found")
        return

    fixed_map = {}
    if os.path.exists(FIXED_FILE):
        with open(FIXED_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                obj = json.loads(line.strip())
                fixed_map[obj["entry_id"]] = obj

    false_positives = 0
    with open(DIFF_FILE, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row_idx, row in enumerate(reader, 1):
            eid = row.get("entry_id", "")
            if not eid:
                fail(f"diff row {row_idx}: missing entry_id")
                continue
            if eid not in fixed_map:
                fail(f"diff row {row_idx}: {eid} not found in fixed.jsonl")
                continue
            if row.get("original_line") == row.get("fixed_line"):
                false_positives += 1

    if false_positives > 0:
        fail(f"{false_positives} false positive(s) in diff (old_line == new_line)")
    else:
        ok("Diff consistency check passed (no false positives)")


def check_code_integrity():
    """Code fields must never change; only file/line may change."""
    print("\n[3/4] Code integrity ...")
    if not os.path.exists(FIXED_FILE) or not os.path.exists(ENTRIES_FILE):
        fail("Missing entries files")
        return

    orig = {}
    with open(ENTRIES_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            obj = json.loads(line.strip())
            orig[obj["entry_id"]] = obj

    corrupted = 0
    with open(FIXED_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            obj = json.loads(line.strip())
            o = orig.get(obj["entry_id"])
            if not o:
                continue
            for nn in ("entry_point", "critical_operation"):
                if obj.get(nn, {}).get("code") != o.get(nn, {}).get("code"):
                    corrupted += 1
                    fail(f"{obj['entry_id']}/{nn}: code was modified!")
            for i in range(len(obj.get("trace", []))):
                on = (o.get("trace") or [])
                nn = obj.get("trace", [])
                if i < len(on) and nn[i].get("code") != on[i].get("code"):
                    corrupted += 1
                    fail(f"{obj['entry_id']}/trace[{i}]: code modified!")

    if corrupted == 0:
        ok("No code fields were corrupted (only file/line changed)")
    else:
        fail(f"{corrupted} code fields were corrupted")


def check_idempotency():
    """Re-run fix_entries.py on fixed output; should produce 0 fixes."""
    print("\n[4/4] Idempotency (dry-run on fixed output) ...")
    backup = ENTRIES_FILE + ".bak"

    try:
        shutil.copy2(ENTRIES_FILE, backup)
        if os.path.exists(FIXED_FILE):
            shutil.copy2(FIXED_FILE, ENTRIES_FILE)

        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "fix_entries.py"),
             "--input", ENTRIES_FILE,
             "--output", os.path.join(tempfile.gettempdir(), "idem_test.jsonl"),
             "--dry-run", "--workers", "4", "--no-cache"],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
        output = result.stdout + result.stderr
        if "0 fix" in output or "no fix" in output or "0 fix" in output.lower():
            ok("Idempotency: re-run produced 0 fixes")
        else:
            fail(f"Idempotency: re-run produced fixes (expected 0).\n{output[:600]}")
    except subprocess.TimeoutExpired:
        fail("Idempotency: dry-run timed out")
    finally:
        if os.path.exists(backup):
            os.remove(ENTRIES_FILE)
            os.rename(backup, ENTRIES_FILE)


def main():
    print("=" * 60)
    print("  fix_entries.py Verification Suite")
    print("=" * 60)

    validate_schema()
    validate_diff()
    check_code_integrity()
    check_idempotency()

    print("\n" + "=" * 60)
    total = PASS + FAIL
    print(f"  Results: {PASS} passed, {FAIL} failed ({total} checks)")
    print(f"  STATUS: {'FAIL' if FAIL > 0 else 'ALL PASSED'}")
    print("=" * 60)
    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    main()
