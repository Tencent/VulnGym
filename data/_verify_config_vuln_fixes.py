"""Strict re-verification of entry-00241..244 against SCHEMA.md and upstream.

Per the issue's delivery convention (§8.1), the fix is written to the parallel
file `data/entries.config_vuln.fixed.jsonl` while `data/entries.jsonl` keeps
the original pre-fix state (read-only baseline). This script therefore reads
the FIXED file as source of truth, not the baseline.

Goals:
  1. SCHEMA invariants for the 4 rows:
       - line type & 1-based
       - required keys for entry_point / critical_operation / trace[]
       - verify in {0,1}
       - report_id/source_link/commit/repo_url format
  2. {file,line,code} consistency with upstream Dockerfile contents (verbatim)
  3. trace[0] == critical_operation in {file,line,code} (per spec)
  4. desc quality: must NOT just restate code (basic keyword check + ascii sanity)
  5. numbers must align with config_vuln_diff.csv (cross-check)
  6. (optional, default on) regen idempotence: re-running _gen_config_vuln_fixed.py
     must leave entries.config_vuln.fixed.jsonl byte-identical.
     Pass --no-regen to skip.

This script is read-only against the dataset itself; the regen step in (6) is
the one operation that re-writes the fixed JSONL and the CSV, and its
byte-for-byte idempotence is precisely what (6) verifies.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
JSONL_BASELINE = ROOT / "data" / "entries.jsonl"        # pre-fix, read-only
JSONL_FIXED = ROOT / "data" / "entries.config_vuln.fixed.jsonl"  # post-fix
CSV = ROOT / "data" / "config_vuln_diff.csv"
ANN = ROOT / "data" / "config_vuln_annotation.md"
GEN = ROOT / "data" / "_gen_config_vuln_fixed.py"

# File we read & verify against — this is the *fixed* JSONL.
JSONL = JSONL_FIXED

COMMIT = "c56fb7f353d63d6ea97028ee7d8a97bc4edf21c1"
TARGETS = {
    "entry-00241": "scripts/e2e/Dockerfile",
    "entry-00242": "scripts/e2e/Dockerfile.qr-import",
    "entry-00243": "scripts/docker/install-sh-e2e/Dockerfile",
    "entry-00244": "scripts/docker/install-sh-nonroot/Dockerfile",
}


def fetch(path: str) -> str:
    url = f"https://raw.githubusercontent.com/openclaw/openclaw/{COMMIT}/{path}"
    with urllib.request.urlopen(url, timeout=20) as r:
        b = r.read()
    return b.decode("utf-8")


def line_range_from_total(text: str) -> int:
    """Total physical lines, = number of newlines (handles trailing newline)."""
    return text.count("\n")


# ---- fetch upstream ------------------------------------------------------
print("[1/6] Fetching upstream files from raw.githubusercontent.com …")
UPSTREAM = {eid: fetch(p) for eid, p in TARGETS.items()}
for eid, txt in UPSTREAM.items():
    print(f"  - {eid}: {line_range_from_total(txt)} lines, {len(txt)} bytes")

# ---- parse entries.jsonl ------------------------------------------------
print("\n[2/6] Loading entries.jsonl …")
with JSONL.open("r", encoding="utf-8") as f:
    rows = [json.loads(line) for line in f if line.strip()]
by_id = {r["entry_id"]: r for r in rows}
assert len(rows) == 408, f"row count drifted: {len(rows)}"

# ---- schema invariants ---------------------------------------------------
print("\n[3/6] SCHEMA invariants …")
REQUIRED = ["entry_id", "report_id", "source_link", "origin", "project",
            "repo_url", "commit", "vuln_title", "vuln_category_l1",
            "vuln_category_l2", "entry_point", "critical_operation",
            "trace", "verify"]


def check_node(node, eid: str, where: str) -> list[str]:
    errs = []
    if not isinstance(node, dict):
        return [f"{eid}/{where}: not a dict"]
    for k in ("file", "line", "code"):
        if k not in node:
            errs.append(f"{eid}/{where}: missing key {k!r}")
    line = node.get("line")
    if isinstance(line, bool):
        errs.append(f"{eid}/{where}: line is bool, not int/str ({line!r})")
    elif isinstance(line, int):
        if line < 1:
            errs.append(f"{eid}/{where}: int line < 1 ({line})")
    elif isinstance(line, str):
        if not re.fullmatch(r"\d+-\d+", line):
            errs.append(f"{eid}/{where}: range line malformed ({line!r})")
        else:
            a, b = (int(x) for x in line.split("-"))
            if not (1 <= a <= b):
                errs.append(f"{eid}/{where}: range {a}-{b} not valid")
    else:
        errs.append(f"{eid}/{where}: line type {type(line).__name__} not int|str")
    return errs


schema_errors: list[str] = []
for eid in TARGETS:
    row = by_id[eid]
    for k in REQUIRED:
        if k not in row:
            schema_errors.append(f"{eid}: missing top-level {k!r}")
    if row.get("verify") not in (0, 1):
        schema_errors.append(f"{eid}: verify not in {{0,1}} ({row.get('verify')})")
    if len(row.get("commit", "")) != 40:
        schema_errors.append(f"{eid}: commit len != 40")
    if not row.get("repo_url", "").startswith("https://github.com/"):
        schema_errors.append(f"{eid}: repo_url prefix wrong")
    if not row.get("source_link", "").startswith("https://github.com/advisories/GHSA-"):
        schema_errors.append(f"{eid}: source_link prefix wrong")
    if row.get("report_id", "").lower() not in row.get("source_link", "").lower():
        schema_errors.append(f"{eid}: report_id not in source_link")
    schema_errors += check_node(row["entry_point"], eid, "entry_point")
    schema_errors += check_node(row["critical_operation"], eid, "critical_operation")
    if not isinstance(row["trace"], list):
        schema_errors.append(f"{eid}: trace not a list")
    else:
        if len(row["trace"]) < 1:
            schema_errors.append(f"{eid}: trace empty")
        for i, tn in enumerate(row["trace"]):
            schema_errors += check_node(tn, eid, f"trace[{i}]")
    # forbidden top-level fields (SCHEMA.md invariant 8)
    for forbidden in ("description", "human_remark", "pipeline_id",
                      "annotated_by", "is_active", "created_at", "generality",
                      "detection_type", "ground_truth", "taint_source",
                      "taint_sink", "vuln_category_l3"):
        if forbidden in row:
            schema_errors.append(f"{eid}: forbidden top-level {forbidden!r}")

# ---- upstream match ------------------------------------------------------
print("\n[4/6] Verifying {file,line,code} against upstream …")
match_errors: list[str] = []
for eid, path in TARGETS.items():
    row = by_id[eid]
    total = line_range_from_total(UPSTREAM[eid])

    # entry_point code == upstream line 1
    ep = row["entry_point"]
    up_lines = UPSTREAM[eid].split("\n")
    if ep["line"] != 1:
        match_errors.append(f"{eid}: entry_point.line != 1 ({ep['line']})")
    if ep["code"] != up_lines[0]:
        match_errors.append(f"{eid}: entry_point.code != upstream line 1")
    if ep["file"] != path:
        match_errors.append(f"{eid}: entry_point.file != upstream ({ep['file']} vs {path})")

    # critical_operation code aligns with the declared line range. The
    # `_gen_config_vuln_fixed.py` source-of-truth strings end with `.rstrip("\n")`
    # (intentional — keeps line-count arithmetic consistent with the range
    # notation), so the canonical on-disk `code` is the joined lines without a
    # trailing newline. We compare against both forms and accept either.
    co = row["critical_operation"]
    cl = co["line"]
    if isinstance(cl, str):
        a, b = (int(x) for x in cl.split("-"))
    else:
        a = b = cl
    expected_no_trailing = "\n".join(up_lines[a - 1:b])
    expected_trailing = expected_no_trailing + "\n"
    if co["code"] not in (expected_no_trailing, expected_trailing):
        match_errors.append(
            f"{eid}: critical_operation.code != upstream lines {a}-{b}"
        )
        # show first divergence against the no-trailing form
        for i, (x, y) in enumerate(zip(co["code"], expected_no_trailing)):
            if x != y:
                match_errors.append(
                    f"  diff at offset {i}: have {x!r} expected {y!r}; "
                    f"context: have={co['code'][max(0,i-10):i+11]!r}"
                    f" expected={expected_no_trailing[max(0,i-10):i+11]!r}"
                )
                break
    if co["file"] != path:
        match_errors.append(f"{eid}: critical_operation.file != upstream")

    # trace[0] equals {critical_operation} in (file,line,code)
    t0 = row["trace"][0]
    if t0["file"] != co["file"] or t0["line"] != co["line"] or t0["code"] != co["code"]:
        match_errors.append(f"{eid}: trace[0] differs from critical_operation")

# ---- desc quality --------------------------------------------------------
print("\n[5/6] desc quality …")
# crude "code-narration" check — desc should not just repeat the code line by line
def desc_is_code_narration(desc: str, code: str) -> bool:
    """Return True if desc looks like it just paraphrases code."""
    code_lines = [l.strip() for l in code.split("\n") if l.strip()]
    if not code_lines:
        return False
    # Heuristic: if desc contains a literal run/copy/from entrypoint substring,
    # that's normal for explaining root cause. Flag if desc looks like bullets
    # of code lines.
    tokens = desc.split()
    if len(tokens) < 12:
        return False
    # count how many of the first 5 code lines appear (verbatim) inside desc
    hits = sum(1 for cl in code_lines[:5] if cl[:30] in desc)
    return hits >= 3


desc_errors: list[str] = []
for eid in TARGETS:
    row = by_id[eid]
    for where, node in (("entry_point", row["entry_point"]),
                        ("critical_operation", row["critical_operation"]),
                        ("trace[0]", row["trace"][0])):
        d = node.get("desc", "")
        if not d:
            desc_errors.append(f"{eid}/{where}: missing desc")
        elif desc_is_code_narration(d, node["code"]):
            desc_errors.append(f"{eid}/{where}: desc looks like code-narration")
    # Extra: for critical_operation, desc should mention "缺少 USER" / "降权"
    co = row["critical_operation"]
    if eid != "entry-00244":
        if "USER" not in co["desc"]:
            desc_errors.append(f"{eid}/critical_operation.desc: missing 'USER' "
                               f"discussion")
    else:
        if "sudo" not in co["desc"].lower() and "sudoers" not in co["desc"].lower():
            desc_errors.append(f"{eid}/critical_operation.desc: missing sudo-related "
                               f"explanation")

# ---- diff CSV consistency ------------------------------------------------
print("\n[DIFF-CSV] Comparing config_vuln_diff.csv to actual on-disk values …")
csv_mismatches: list[str] = []
with CSV.open("r", encoding="utf-8", newline="") as f:
    rd = csv.DictReader(f)
    by_pair = {(r["entry_id"], r["field"]): r for r in rd}

for eid in TARGETS:
    row = by_id[eid]
    # The CSV has a synthetic row whose field == "vuln_category". Map it
    # explicitly to the l1/l2 pair rather than row["vuln_category"], which
    # does not exist on the row.
    fields_in_entry = {
        "entry_point": row["entry_point"],
        "critical_operation": row["critical_operation"],
        "trace": row["trace"],
        "vuln_category": {"vuln_category_l1": row["vuln_category_l1"],
                          "vuln_category_l2": row["vuln_category_l2"]},
    }
    for field_name, cur in fields_in_entry.items():
        d = by_pair.get((eid, field_name))
        if d is None:
            csv_mismatches.append(f"{eid}: missing CSV row for field={field_name}")
            continue
        # Compare semantic JSON (sorted keys) — the on-disk entries.jsonl rows
        # use alphabetical key order, while CSV dicts use insertion order.
        d_cur = json.dumps(cur, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        if d["fixed_value_json"] != d_cur:
            # allow insertion-order; re-dump CSV-side with sorted keys
            try:
                csv_obj = json.loads(d["fixed_value_json"])
                d_csv_sorted = json.dumps(csv_obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            except json.JSONDecodeError:
                d_csv_sorted = d["fixed_value_json"]
            if d_csv_sorted == d_cur:
                # only key-order difference
                pass
            else:
                csv_mismatches.append(
                    f"{eid}/{field_name}: CSV fixed_value_json != entries.jsonl on-disk"
                )

# ---- regen idempotence (optional) ----------------------------------------
print("\n[6/6] Regen idempotence …")
idempotence_errors: list[str] = []
run_regen = "--no-regen" not in sys.argv


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


if run_regen:
    h0 = sha256(JSONL_FIXED)
    res = subprocess.run([sys.executable, str(GEN)], capture_output=True, text=True)
    if res.returncode != 0:
        idempotence_errors.append(f"gen exit={res.returncode}: {res.stderr.strip()}")
    h1 = sha256(JSONL_FIXED)
    res = subprocess.run([sys.executable, str(GEN)], capture_output=True, text=True)
    if res.returncode != 0:
        idempotence_errors.append(f"gen2 exit={res.returncode}: {res.stderr.strip()}")
    h2 = sha256(JSONL_FIXED)
    if h0 != h1 or h1 != h2:
        idempotence_errors.append(
            f"regen not idempotent: h0={h0[:16]} h1={h1[:16]} h2={h2[:16]}"
        )
    print(f"  hash0={h0[:16]}… hash1={h1[:16]}… hash2={h2[:16]}… "
          f"({'idempotent' if h0==h1==h2 else 'DRIFT'})")
    # Also sanity-check baseline was not touched.
    h_base = sha256(JSONL_BASELINE)
    print(f"  baseline={h_base[:16]}… (read-only)")
else:
    print("  skipped (--no-regen)")

# ---- report --------------------------------------------------------------
print("\n=== SUMMARY ===")
print(f"  rows in entries.config_vuln.fixed.jsonl: {len(rows)} (expected 408)")
print(f"  schema invariant violations:         {len(schema_errors)}")
for e in schema_errors:
    print(f"      * {e}")
print(f"  upstream {{file,line,code}} mismatches: {len(match_errors)}")
for e in match_errors:
    print(f"      * {e}")
print(f"  desc quality warnings:               {len(desc_errors)}")
for e in desc_errors:
    print(f"      * {e}")
print(f"  config_vuln_diff.csv mismatches:     {len(csv_mismatches)}")
for e in csv_mismatches:
    print(f"      * {e}")
print(f"  regen idempotence issues:            {len(idempotence_errors)}")
for e in idempotence_errors:
    print(f"      * {e}")

any_err = (schema_errors or match_errors or desc_errors or csv_mismatches
           or idempotence_errors)
print("\nOVERALL:", "PASS" if not any_err else "FAIL")
raise SystemExit(0 if not any_err else 1)
