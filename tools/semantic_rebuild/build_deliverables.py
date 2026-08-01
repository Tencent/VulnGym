# -*- coding: utf-8 -*-
"""Build issue #6 deliverables from AFTER.json node packs."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tools" / "semantic_rebuild" / "out"
ENTRIES = ROOT / "data" / "entries.jsonl"
IDS = [
    "entry-00099",
    "entry-00100",
    "entry-00103",
    "entry-00176",
    "entry-00511",
    "entry-00512",
]

# Short reasons for CSV (human review). Detailed text lives in DECISION/CANDIDATES.
REASONS = {
    ("entry-00099", "entry_point"): "decorator→executeManually(req.body) so external input enters chain",
    ("entry-00099", "critical_operation"): "RCE sink evaluateExpression; sanitizer def rejected",
    ("entry-00099", "trace"): "keep gap(visitMemberExpression)/regex; drop brace-only noise",
    ("entry-00100", "entry_point"): "unchanged position; desc clarified",
    ("entry-00100", "critical_operation"): "sanitizer def→evaluateExpression sink",
    ("entry-00100", "trace"): "sanitizer def demoted to trace",
    ("entry-00103", "entry_point"): "brace `}`→setResponseHeaders",
    ("entry-00103", "critical_operation"): "keep missing-trim locus; desc clarified",
    ("entry-00103", "trace"): "call-site + streaming; no duplicate entry body",
    ("entry-00176", "entry_point"): "unchanged Python getNodeParameter",
    ("entry-00176", "critical_operation"): "static BLOCKED_* → visit_Attribute membership",
    ("entry-00176", "trace"): "add validate() visit; document getattr not CVE path",
    ("entry-00511", "entry_point"): "unchanged extend injection",
    ("entry-00511", "critical_operation"): "keep unchecked native select; patch blocks names before lookup (not apply)",
    ("entry-00511", "trace"): "apply demoted to trace; patch evidence in PATCH_NOTES",
    ("entry-00512", "entry_point"): "method head→vmEvaluator.evaluate",
    ("entry-00512", "critical_operation"): "position kept (writable __sanitize); desc tightened",
    ("entry-00512", "trace"): "defineProperty contrast + path.replace; no exact critical dup",
}


def load_after(eid: str) -> dict:
    return json.loads((ROOT / "tools" / "semantic_rebuild" / eid / "AFTER.json").read_text(encoding="utf-8"))


def node_key(n: dict) -> tuple:
    return (n.get("file"), str(n.get("line")), (n.get("code") or "").strip())


def change_kind(before: dict, after: dict) -> str:
    if node_key(before) != node_key(after):
        return "position_or_code"
    if (before.get("desc") or "") != (after.get("desc") or ""):
        return "desc_only"
    return "unchanged"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    after_map = {eid: load_after(eid) for eid in IDS}
    originals = {}
    for line in ENTRIES.read_text(encoding="utf-8").splitlines():
        o = json.loads(line)
        if o["entry_id"] in after_map:
            originals[o["entry_id"]] = o

    fixed_rows = []
    diff_rows = []
    for eid in IDS:
        before = originals[eid]
        after = after_map[eid]
        fixed = dict(before)
        for field in ("entry_point", "critical_operation", "trace", "verify"):
            if field in after:
                fixed[field] = after[field]
        fixed["verify"] = 0
        fixed_rows.append(fixed)

        for field in ("entry_point", "critical_operation"):
            b, a = before[field], fixed[field]
            kind = change_kind(b, a)
            if kind == "unchanged":
                continue
            diff_rows.append(
                {
                    "entry_id": eid,
                    "field": field,
                    "change_kind": kind,
                    "before_file": b.get("file"),
                    "before_line": b.get("line"),
                    "before_code": (b.get("code") or "")[:160],
                    "after_file": a.get("file"),
                    "after_line": a.get("line"),
                    "after_code": (a.get("code") or "")[:160],
                    "reason": REASONS.get((eid, field), "semantic_rebuild"),
                }
            )

        bt, at = before.get("trace") or [], fixed.get("trace") or []
        trace_changed = [node_key(x) for x in bt] != [node_key(x) for x in at] or any(
            (x.get("desc") or "") != (y.get("desc") or "") for x, y in zip(bt, at)
        ) or len(bt) != len(at)
        if trace_changed:
            diff_rows.append(
                {
                    "entry_id": eid,
                    "field": "trace",
                    "change_kind": "trace_rewrite",
                    "before_file": f"len={len(bt)}",
                    "before_line": "",
                    "before_code": "; ".join(f"{t.get('file')}:{t.get('line')}" for t in bt[:4]),
                    "after_file": f"len={len(at)}",
                    "after_line": "",
                    "after_code": "; ".join(f"{t.get('file')}:{t.get('line')}" for t in at[:4]),
                    "reason": REASONS.get((eid, "trace"), "rewritten_for_semantic_flow"),
                }
            )

    fixed_path = OUT / "entries.fixed.jsonl"
    with fixed_path.open("w", encoding="utf-8", newline="\n") as f:
        for row in fixed_rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    csv_path = OUT / "semantic_diff.csv"
    fields = [
        "entry_id",
        "field",
        "change_kind",
        "before_file",
        "before_line",
        "before_code",
        "after_file",
        "after_line",
        "after_code",
        "reason",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(diff_rows)

    print("wrote", fixed_path)
    print("wrote", csv_path)
    print("entries", len(fixed_rows), "diff_rows", len(diff_rows))


if __name__ == "__main__":
    main()
