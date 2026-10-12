# -*- coding: utf-8 -*-
"""Independent verifier for location-repair artifacts (Diff Pack item 5)."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
from _diffpack_lib import (  # noqa: E402
    OUT,
    ROOT,
    apply_fix_to_entry,
    classify_our_fix,
    load_fix_csv,
    load_fix_mod,
    parse_line,
)

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


def schema_entry(e: dict, mod) -> list[str]:
    errs = []
    for k in FORBIDDEN:
        if k in e:
            errs.append(f"forbidden {k}")
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
            errs.append(f"{path} extra {extra}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--entries", type=Path, default=ROOT / "data" / "entries.jsonl")
    ap.add_argument("--fixed", type=Path, default=OUT / "entries.fixed.jsonl")
    ap.add_argument("--fix-diff", type=Path, default=OUT / "fix_diff.csv")
    ap.add_argument("--cache", type=Path, default=ROOT / ".repo_cache")
    ap.add_argument("--idempotency-sample", type=int, default=25)
    ap.add_argument("--out-report", type=Path, default=OUT / "VERIFY_REPORT.md")
    ap.add_argument("--out-json", type=Path, default=OUT / "VERIFY_REPORT.json")
    args = ap.parse_args()

    mod = load_fix_mod()
    report: dict = {"ok": True, "checks": {}}

    # Load artifacts
    fixes = load_fix_csv(args.fix_diff)
    originals: dict[str, dict] = {}
    with args.entries.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                originals[e["entry_id"]] = e

    fixed_rows: list[dict] = []
    if args.fixed.is_file():
        with args.fixed.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    fixed_rows.append(json.loads(line))
    else:
        # rebuild from fix_diff
        for eid, e in originals.items():
            fixed_rows.append(apply_fix_to_entry(e, fixes, mod))

    report["checks"]["row_count"] = {
        "original": len(originals),
        "fixed": len(fixed_rows),
        "fix_diff": len(fixes),
        "ok": len(fixed_rows) == len(originals) == 408,
    }
    if not report["checks"]["row_count"]["ok"]:
        report["ok"] = False

    # Schema
    schema_errs = []
    for e in fixed_rows:
        errs = schema_entry(e, mod)
        if errs:
            schema_errs.append({"entry_id": e["entry_id"], "errs": errs[:5]})
    report["checks"]["schema"] = {
        "errors": len(schema_errs),
        "samples": schema_errs[:8],
    }
    if schema_errs:
        report["ok"] = False

    # fix_diff consistency: every fix must be reflected in fixed jsonl
    fixed_by_id = {e["entry_id"]: e for e in fixed_rows}
    inconsist = []
    for (eid, fp), r in fixes.items():
        e = fixed_by_id.get(eid)
        if not e:
            inconsist.append({"entry_id": eid, "err": "missing in fixed"})
            continue
        node = None
        for path, n in mod.iter_nodes(e):
            if path == fp:
                node = n
                break
        if node is None:
            inconsist.append({"entry_id": eid, "field": fp, "err": "missing node"})
            continue
        nf = r.get("new_file") or r.get("old_file")
        nl = parse_line(r.get("new_line") or r.get("old_line"))
        if node.get("file") != nf or node.get("line") != nl:
            inconsist.append(
                {
                    "entry_id": eid,
                    "field": fp,
                    "err": "fixed jsonl != fix_diff",
                    "jsonl": {"file": node.get("file"), "line": node.get("line")},
                    "diff": {"file": nf, "line": nl},
                }
            )
    report["checks"]["fix_diff_consistency"] = {
        "mismatches": len(inconsist),
        "samples": inconsist[:8],
    }
    if inconsist:
        report["ok"] = False

    # Classification sanity
    classes = {}
    for r in fixes.values():
        c = classify_our_fix(r)
        classes[c] = classes.get(c, 0) + 1
    report["checks"]["classification"] = classes

    # Idempotency sample (prefer line_moved)
    ranked = sorted(
        fixes.values(),
        key=lambda r: 0 if classify_our_fix(r) == "line_moved" else 1,
    )
    picked = []
    seen = set()
    for r in ranked:
        if r["entry_id"] in seen:
            continue
        seen.add(r["entry_id"])
        picked.append(r)
        if len(picked) >= args.idempotency_sample:
            break
    ok = fail = skip = 0
    fails = []
    for r in picked:
        e = originals[r["entry_id"]]
        node = None
        for path, n in mod.iter_nodes(e):
            if path == r["field_path"]:
                node = n
                break
        if not node:
            skip += 1
            continue
        try:
            repo = mod.ensure_repo(e["repo_url"], e["commit"], args.cache)
        except Exception as ex:
            skip += 1
            fails.append({"entry_id": r["entry_id"], "status": "skip", "err": str(ex)[:100]})
            continue
        check = {
            "file": r.get("new_file") or r["old_file"],
            "line": parse_line(r.get("new_line") or r["old_line"]),
            "code": node["code"],
        }
        result = mod.repair_node(repo, check, allow_repo_wide=False)
        if result.status == "ok":
            ok += 1
        else:
            fail += 1
            fails.append(
                {
                    "entry_id": r["entry_id"],
                    "field": r["field_path"],
                    "got": result.status,
                    "reason": result.reason,
                }
            )
    report["checks"]["idempotency"] = {
        "sampled": len(picked),
        "ok": ok,
        "fail": fail,
        "skip": skip,
        "failures": fails[:10],
    }
    if fail:
        report["ok"] = False

    args.out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    idemp = report["checks"]["idempotency"]
    md = [
        "# VERIFY_REPORT — location repair artifacts\n\n",
        f"Overall ok: **{report['ok']}**\n\n",
        f"- rows original/fixed/fix_diff: {report['checks']['row_count']}\n",
        f"- schema errors: **{report['checks']['schema']['errors']}**\n",
        f"- fix_diff mismatches: **{report['checks']['fix_diff_consistency']['mismatches']}**\n",
        f"- classification: `{report['checks']['classification']}`\n",
        f"- idempotency: ok={idemp['ok']} fail={idemp['fail']} skip={idemp['skip']} "
        f"(sampled {idemp['sampled']})\n",
    ]
    if idemp["failures"]:
        md.append("\nFailures / skips:\n\n")
        for d in idemp["failures"]:
            md.append(f"- `{d}`\n")
    args.out_report.write_text("".join(md), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2)[:2500])
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
