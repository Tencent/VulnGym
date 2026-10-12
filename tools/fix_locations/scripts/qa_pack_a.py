# -*- coding: utf-8 -*-
"""GREEN QA: schema smoke + idempotency on our current fix_diff / partial JSONL."""
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parents[1]
OUT = HERE / "out"
ENTRIES = ROOT / "data" / "entries.jsonl"
FIX = OUT / "fix_diff.csv"
PARTIAL = OUT / "entries.fixed.partial.jsonl"
CACHE = ROOT / ".repo_cache"

# Load helper functions from main script
sys.path.insert(0, str(HERE))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "fix_code_locations", HERE / "fix_code_locations.py"
)
mod = importlib.util.module_from_spec(spec)
assert spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

LINE_RE = re.compile(r"^(\d+)$|^(\d+)-(\d+)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN = {
    "description",
    "human_remark",
    "pipeline_id",
    "annotated_by",
    "is_active",
    "created_at",
    "generality",
    "detection_type",
    "ground_truth",
    "taint_source",
    "taint_sink",
    "vuln_category_l3",
}


def check_line(v) -> str | None:
    if isinstance(v, int):
        return None if v >= 1 else f"line int <1: {v}"
    if isinstance(v, str):
        m = LINE_RE.fullmatch(v)
        if not m:
            return f"bad line str: {v!r}"
        if m.group(1):
            return None
        a, b = int(m.group(2)), int(m.group(3))
        return None if 1 <= a <= b else f"bad range: {v}"
    return f"bad line type: {type(v)}"


def schema_check_entry(e: dict) -> list[str]:
    errs = []
    for k in FORBIDDEN:
        if k in e:
            errs.append(f"forbidden field {k}")
    if e.get("verify") not in (0, 1):
        errs.append(f"verify={e.get('verify')!r}")
    if not COMMIT_RE.fullmatch(e.get("commit") or ""):
        errs.append("bad commit")
    if not str(e.get("repo_url") or "").startswith("https://github.com/"):
        errs.append("bad repo_url")
    for path, node in mod.iter_nodes(e):
        for key in ("file", "line", "code"):
            if key not in node:
                errs.append(f"{path} missing {key}")
        if "line" in node:
            msg = check_line(node["line"])
            if msg:
                errs.append(f"{path} {msg}")
        extra = set(node) - {"file", "line", "code", "desc"}
        if extra:
            errs.append(f"{path} extra keys {extra}")
    return errs


def latest_partial_by_id() -> dict[str, dict]:
    """Resume appends may duplicate; keep last occurrence per entry_id."""
    latest: dict[str, dict] = {}
    if not PARTIAL.is_file():
        return latest
    with PARTIAL.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            latest[e["entry_id"]] = e
    return latest


def build_merged_fixed() -> tuple[list[dict], dict]:
    """Apply fix_diff onto original entries for all entries (408)."""
    fixes = list(csv.DictReader(FIX.open(encoding="utf-8")))
    by_key: dict[tuple[str, str], dict] = {}
    for r in fixes:
        by_key[(r["entry_id"], r["field_path"])] = r

    out_rows = []
    with ENTRIES.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            e = json.loads(json.dumps(e))  # copy
            for path, node in mod.iter_nodes(e):
                r = by_key.get((e["entry_id"], path))
                if not r:
                    continue
                if r.get("new_file"):
                    node["file"] = r["new_file"]
                if r.get("new_line") not in (None, ""):
                    nl = r["new_line"]
                    node["line"] = int(nl) if str(nl).isdigit() else nl
            out_rows.append(e)
    meta = {"source_entries": len(out_rows), "fix_rows_applied": len(fixes)}
    return out_rows, meta


def idempotency_check(sample_n: int = 25) -> dict:
    """Re-verify that each sampled fix still uniquely matches at new location."""
    fixes = list(csv.DictReader(FIX.open(encoding="utf-8")))
    # diversify: prefer line_moved then range_expand
    def kind(r):
        old, new = str(r["old_line"]), str(r["new_line"])
        if old.isdigit() and "-" in new and new.split("-", 1)[0] == old:
            return 1
        return 0

    fixes_sorted = sorted(fixes, key=kind)  # line moves first
    # unique entry sample
    picked = []
    seen_e = set()
    for r in fixes_sorted:
        if r["entry_id"] in seen_e:
            continue
        seen_e.add(r["entry_id"])
        picked.append(r)
        if len(picked) >= sample_n:
            break
    # also add a few more range expands from remaining
    for r in fixes:
        if len(picked) >= sample_n + 10:
            break
        if r not in picked:
            picked.append(r)

    entries: dict[str, dict] = {}
    with ENTRIES.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            entries[e["entry_id"]] = e

    ok = fail = skip = 0
    details = []
    for r in picked[: sample_n + 5]:
        e = entries[r["entry_id"]]
        # find code from original entry at field
        node = None
        for path, n in mod.iter_nodes(e):
            if path == r["field_path"]:
                node = n
                break
        if not node:
            skip += 1
            continue
        try:
            repo = mod.ensure_repo(e["repo_url"], e["commit"], CACHE)
        except Exception as ex:
            skip += 1
            details.append({"entry_id": r["entry_id"], "status": "skip_fetch", "err": str(ex)[:120]})
            continue
        new_file = r.get("new_file") or r["old_file"]
        new_line = r.get("new_line") or r["old_line"]
        if str(new_line).isdigit():
            new_line = int(new_line)
        check_node = {"file": new_file, "line": new_line, "code": node["code"]}
        result = mod.repair_node(repo, check_node, allow_repo_wide=False)
        if result.status == "ok":
            ok += 1
            details.append({"entry_id": r["entry_id"], "field_path": r["field_path"], "status": "ok"})
        else:
            fail += 1
            details.append(
                {
                    "entry_id": r["entry_id"],
                    "field_path": r["field_path"],
                    "status": "fail",
                    "got": result.status,
                    "reason": result.reason,
                }
            )
    return {
        "sampled": len(picked[: sample_n + 5]),
        "ok": ok,
        "fail": fail,
        "skip": skip,
        "details_fail": [d for d in details if d.get("status") == "fail"],
        "details_skip": [d for d in details if d.get("status", "").startswith("skip")],
    }


def diagnose_fetch_failed() -> dict:
    info = {"entries": ["entry-00097", "entry-00098"], "commit": None, "repo_url": None}
    with ENTRIES.open(encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e["entry_id"] == "entry-00097":
                info["repo_url"] = e["repo_url"]
                info["commit"] = e["commit"]
                info["project"] = e.get("project")
                break
    repo_url = info["repo_url"]
    commit = info["commit"]
    path = mod.repo_cache_dir(CACHE, repo_url)
    steps = []
    exists = (path / ".git").exists()
    steps.append({"cache_path": str(path), "git_exists": exists})
    if not exists:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
            steps.append({"clone": "ok"})
        except subprocess.CalledProcessError as e:
            steps.append({"clone": "fail", "stderr": (e.stderr or "")[-500:]})
            info["steps"] = steps
            info["verdict"] = "clone_failed"
            return info

    # try cat-file
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=path,
        capture_output=True,
        text=True,
    )
    steps.append({"cat_file_before_fetch": probe.returncode})
    if probe.returncode != 0:
        for args in (
            ["git", "fetch", "--depth", "1", "origin", commit],
            ["git", "fetch", "origin", commit],
            ["git", "fetch", "--unshallow"],
        ):
            fr = subprocess.run(args, cwd=path, capture_output=True, text=True)
            steps.append(
                {
                    "cmd": " ".join(args),
                    "rc": fr.returncode,
                    "stderr": (fr.stderr or "")[-300:],
                }
            )
            probe = subprocess.run(
                ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                cwd=path,
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                break
    steps.append({"cat_file_after": probe.returncode})
    if probe.returncode == 0:
        co = subprocess.run(
            ["git", "checkout", "--force", commit],
            cwd=path,
            capture_output=True,
            text=True,
        )
        steps.append(
            {
                "checkout_rc": co.returncode,
                "stderr": (co.stderr or "")[-300:],
            }
        )
        info["verdict"] = "ok" if co.returncode == 0 else "checkout_failed_after_fetch"
    else:
        # remote membership
        ls = subprocess.run(
            ["git", "ls-remote", repo_url, commit],
            capture_output=True,
            text=True,
        )
        steps.append(
            {
                "ls_remote_rc": ls.returncode,
                "stdout": (ls.stdout or "")[:200],
                "stderr": (ls.stderr or "")[-200:],
            }
        )
        info["verdict"] = (
            "commit_not_on_remote" if not (ls.stdout or "").strip() else "local_fetch_issue"
        )
    info["steps"] = steps
    return info


def main() -> None:
    report: dict = {"ok": True}

    # 1) merge fixed jsonl
    merged, meta = build_merged_fixed()
    merged_path = OUT / "entries.fixed.jsonl"
    with merged_path.open("w", encoding="utf-8") as f:
        for e in merged:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
    report["merged_fixed"] = {**meta, "path": str(merged_path), "rows": len(merged)}

    # 2) schema on merged
    schema_errs = []
    for e in merged:
        errs = schema_check_entry(e)
        if errs:
            schema_errs.append({"entry_id": e["entry_id"], "errs": errs[:5]})
    report["schema"] = {
        "checked": len(merged),
        "entries_with_errors": len(schema_errs),
        "samples": schema_errs[:10],
    }
    if schema_errs:
        report["ok"] = False

    # 3) partial stats
    latest = latest_partial_by_id()
    report["partial"] = {
        "unique_ids": len(latest),
        "file": str(PARTIAL),
        "note": "partial may contain resume duplicates; merged fixed is authoritative",
    }

    # 4) idempotency
    report["idempotency"] = idempotency_check(25)
    if report["idempotency"]["fail"]:
        report["ok"] = False

    # 5) fetch diagnose
    report["fetch_failed"] = diagnose_fetch_failed()

    out_json = OUT / "QA_PACK_A.json"
    out_md = OUT / "QA_PACK_A.md"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    ff = report["fetch_failed"]
    idemp = report["idempotency"]
    lines = [
        "# QA Pack A — idempotency / schema / fetch_failed\n\n",
        f"Overall ok: **{report['ok']}**\n\n",
        "## Schema (merged entries.fixed.jsonl)\n\n",
        f"- rows: {report['schema']['checked']}\n",
        f"- entries with errors: **{report['schema']['entries_with_errors']}**\n\n",
        "## Idempotency (re-check fixed locations against source)\n\n",
        f"- sampled: {idemp['sampled']}\n",
        f"- ok: **{idemp['ok']}**\n",
        f"- fail: **{idemp['fail']}**\n",
        f"- skip: {idemp['skip']}\n\n",
    ]
    if idemp["details_fail"]:
        lines.append("Failures:\n\n")
        for d in idemp["details_fail"][:10]:
            lines.append(f"- `{d}`\n")
        lines.append("\n")
    lines += [
        "## fetch_failed diagnosis (entry-00097 / 00098)\n\n",
        f"- repo: `{ff.get('repo_url')}`\n",
        f"- commit: `{ff.get('commit')}`\n",
        f"- verdict: **{ff.get('verdict')}**\n\n",
        "See `QA_PACK_A.json` for git step log.\n\n",
        f"## Merged artifact\n\n- `{merged_path}` ({len(merged)} rows) — built by applying fix_diff onto original entries.\n",
    ]
    out_md.write_text("".join(lines), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2)[:4000])
    print(f"\nWrote {out_md}")


if __name__ == "__main__":
    main()
