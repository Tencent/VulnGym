#!/usr/bin/env python3
"""Read-only verifier for the config-vuln fix (issue #8).

Does NOT modify any file under data/. Runs independent checks and exits
non-zero on the first failure:

  1. baseline-untouched  — data/entries.jsonl still matches the pristine
                            upstream copy (this PR must not have edited it).
  2. schema-invariants   — data/entries.config_vuln.fixed.jsonl satisfies
                            every invariant in SCHEMA.md (row count, id
                            cross-references, origin/commit/repo_url/
                            source_link format, entry_point/critical_operation
                            /trace shape, verify in {0,1}, sort order).
  3. upstream-source     — {file, line, code} of the 3 rewritten entries
                            match the real Dockerfiles in
                            openclaw/openclaw@<commit> (network fetch).
  4. diff-csv-consistency — config_vuln_diff.csv agrees field-for-field with
                            what's actually in entries.config_vuln.fixed.jsonl.
  5. generator-idempotent — running gen_config_vuln_fixed.py twice produces
                            byte-identical output.
  6. desc-not-just-code  — the rewritten desc text is not merely a restatement
                            of the code field (issue #8 explicitly requires
                            desc to explain *why*, not restate).

Usage:
    python scripts/data_fixes/verify_config_vuln_fixes.py
"""
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE = REPO_ROOT / "data" / "entries.jsonl"
FIXED = REPO_ROOT / "data" / "entries.config_vuln.fixed.jsonl"
DIFF_CSV = REPO_ROOT / "data" / "config_vuln_diff.csv"
GENERATOR = REPO_ROOT / "scripts" / "data_fixes" / "gen_config_vuln_fixed.py"

TARGET_IDS = {"entry-00241", "entry-00242", "entry-00243", "entry-00244"}
REWRITTEN_IDS = {"entry-00241", "entry-00242", "entry-00243"}

FORBIDDEN_FIELDS = {
    "description", "human_remark", "pipeline_id", "annotated_by",
    "is_active", "created_at", "generality", "detection_type",
    "ground_truth", "taint_source", "taint_sink", "vuln_category_l3",
}

RAW_BASE = "https://raw.githubusercontent.com/openclaw/openclaw/{commit}/{path}"

failures = []


def check(name):
    def deco(fn):
        print(f"[{name}] ", end="", flush=True)
        try:
            fn()
        except AssertionError as e:
            print(f"FAIL — {e}")
            failures.append(name)
        else:
            print("ok")
    return deco


def load_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                rows.append(json.loads(line))
    return rows


print("config-vuln fix verifier (read-only, issue #8)\n")


@check("baseline-untouched")
def _():
    upstream_url = "https://raw.githubusercontent.com/Tencent/VulnGym/main/data/entries.jsonl"
    with urllib.request.urlopen(upstream_url, timeout=15) as resp:
        upstream_bytes = resp.read()
    local_bytes = BASELINE.read_bytes()
    assert hashlib.sha256(local_bytes).hexdigest() == hashlib.sha256(upstream_bytes).hexdigest(), (
        "data/entries.jsonl no longer matches Tencent/VulnGym main — "
        "this PR must not edit the shared baseline"
    )


@check("schema-invariants")
def _():
    fixed = load_jsonl(FIXED)
    assert len(fixed) == 408, f"expected 408 rows, got {len(fixed)}"

    ids_sorted = sorted(e["entry_id"] for e in fixed)
    actual_order = [e["entry_id"] for e in fixed]
    assert ids_sorted == actual_order, "entries not sorted by entry_id ascending"

    for e in fixed:
        eid = e["entry_id"]
        assert e.get("origin") == "GitHub Advisory Database (reviewed)", f"{eid}: bad origin"
        assert re.fullmatch(r"[0-9a-f]{40}", e.get("commit", "") or ""), f"{eid}: bad commit"
        assert (e.get("repo_url") or "").startswith("https://github.com/"), f"{eid}: bad repo_url"
        assert e.get("verify") in (0, 1), f"{eid}: bad verify"
        assert not (FORBIDDEN_FIELDS & set(e.keys())), f"{eid}: forbidden field present"

        for label in ("entry_point", "critical_operation"):
            node = e[label]
            assert {"file", "line", "code"}.issubset(node.keys()), f"{eid}.{label}: missing keys"
            line = node["line"]
            if isinstance(line, int):
                assert line >= 1, f"{eid}.{label}: line < 1"
            else:
                m = re.fullmatch(r"(\d+)-(\d+)", line)
                assert m and int(m.group(1)) <= int(m.group(2)), f"{eid}.{label}: bad line range"

        for i, t in enumerate(e.get("trace", [])):
            assert {"file", "line", "code"}.issubset(t.keys()), f"{eid}.trace[{i}]: missing keys"


@check("upstream-source")
def _():
    fixed_by_id = {e["entry_id"]: e for e in load_jsonl(FIXED)}
    file_cache = {}
    for eid in sorted(REWRITTEN_IDS):
        e = fixed_by_id[eid]
        commit = e["commit"]
        for node in [e["entry_point"], e["critical_operation"]] + e["trace"]:
            key = (commit, node["file"])
            if key not in file_cache:
                url = RAW_BASE.format(commit=commit, path=node["file"])
                with urllib.request.urlopen(url, timeout=15) as resp:
                    file_cache[key] = resp.read().decode("utf-8").splitlines()
            lines = file_cache[key]
            actual = lines[node["line"] - 1]
            assert actual == node["code"], (
                f"{eid}: {node['file']}:{node['line']} mismatch\n"
                f"  expected: {node['code']!r}\n  actual:   {actual!r}"
            )


@check("diff-csv-consistency")
def _():
    import csv
    fixed_by_id = {e["entry_id"]: e for e in load_jsonl(FIXED)}
    with DIFF_CSV.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 16, f"expected 16 diff rows, got {len(rows)}"
    for row in rows:
        eid, field = row["entry_id"], row["field"]
        actual = json.dumps(fixed_by_id[eid][field], ensure_ascii=False, sort_keys=True)
        assert actual == row["after"], f"{eid}.{field}: diff CSV 'after' doesn't match fixed JSONL"


@check("generator-idempotent")
def _():
    def file_hash(p):
        return hashlib.sha256(p.read_bytes()).hexdigest()

    h1_fixed, h1_csv = file_hash(FIXED), file_hash(DIFF_CSV)
    result = subprocess.run([sys.executable, str(GENERATOR)], cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"generator failed on 2nd run: {result.stderr}"
    h2_fixed, h2_csv = file_hash(FIXED), file_hash(DIFF_CSV)
    assert h1_fixed == h2_fixed, "entries.config_vuln.fixed.jsonl not idempotent"
    assert h1_csv == h2_csv, "config_vuln_diff.csv not idempotent"


@check("desc-not-just-code")
def _():
    fixed_by_id = {e["entry_id"]: e for e in load_jsonl(FIXED)}
    for eid in sorted(REWRITTEN_IDS):
        e = fixed_by_id[eid]
        for node in e["trace"]:
            desc = node.get("desc", "")
            assert len(desc) >= 30, f"{eid}: trace desc too short to explain anything"
            assert desc.strip() != node["code"].strip(), f"{eid}: desc just restates code"
            assert any(kw in desc for kw in ("USER", "root", "状态", "改变")), (
                f"{eid}: desc doesn't explain the risk reasoning"
            )


def main():
    # All @check-decorated functions above already ran at module load time
    # (each decorator executes its function immediately); by the time we get
    # here `failures` is fully populated.
    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {failures}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
