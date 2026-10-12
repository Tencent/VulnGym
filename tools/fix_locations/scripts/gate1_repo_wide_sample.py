# -*- coding: utf-8 -*-
"""G1: verify sample classification against source."""
from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools" / "fix_locations" / "fix_code_locations.py"
spec = importlib.util.spec_from_file_location("fix_code_locations", SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

ids = {"entry-00164", "entry-00193", "entry-00298"}
entries: dict[str, dict] = {}
with (ROOT / "data" / "entries.jsonl").open(encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        if e["entry_id"] in ids:
            entries[e["entry_id"]] = e

nh_path = ROOT / "tools" / "fix_locations" / "out" / "repo_wide_sample" / "needs_human.csv"
nh = list(csv.DictReader(nh_path.open(encoding="utf-8")))


def get_node(e: dict, path: str):
    if path == "entry_point":
        return e["entry_point"]
    if path == "critical_operation":
        return e["critical_operation"]
    i = int(path[path.find("[") + 1 : path.find("]")])
    return e["trace"][i]


checks = []
for row in nh:
    e = entries[row["entry_id"]]
    node = get_node(e, row["field_path"])
    repo = mod.ensure_repo(e["repo_url"], e["commit"], ROOT / ".repo_cache")
    code = node["code"]
    if mod.is_degenerate_code(code):
        checks.append(
            {
                **{k: row[k] for k in ("entry_id", "field_path", "reason")},
                "verify": "degenerate_ok",
                "hit_count": None,
                "code_preview": repr(code)[:80],
            }
        )
        continue
    hits = []
    for path in mod.list_repo_files(repo):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        hit = mod.find_unique_in_lines(lines, code)
        if hit:
            rel = path.relative_to(repo).as_posix()
            hits.append((rel, hit.as_json()))
            if len(hits) > 3:
                break
    if row["reason"] == "repo_wide_no_match" and len(hits) == 0:
        verify = "PASS_no_match"
    elif row["reason"] == "repo_wide_ambiguous" and len(hits) > 1:
        verify = "PASS_ambiguous"
    else:
        verify = "FAIL_mismatch"
    checks.append(
        {
            "entry_id": row["entry_id"],
            "field": row["field_path"],
            "reason": row["reason"],
            "hit_count": len(hits),
            "hits_sample": hits[:3],
            "code_preview": repr(code)[:120],
            "verify": verify,
        }
    )

out = {
    "repo_wide_unique": 0,
    "checks": checks,
    "all_pass": all(
        c["verify"].startswith("PASS") or c["verify"] == "degenerate_ok" for c in checks
    ),
    "gate_rule": "0 unique OK if no_match/ambiguous/degenerate classified correctly",
}
print(json.dumps(out, ensure_ascii=False, indent=2))
(ROOT / "tools" / "fix_locations" / "out" / "repo_wide_sample" / "GATE1.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
)
sys.exit(0 if out["all_pass"] else 1)
