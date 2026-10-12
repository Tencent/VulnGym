# -*- coding: utf-8 -*-
"""Shared helpers for Diff Pack (classify / load CSVs). GREEN only."""
from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
OUT = HERE / "out"
ROOT = HERE.parents[1]
COMP = OUT / "competitor_diffs"


def load_fix_mod():
    spec = importlib.util.spec_from_file_location(
        "fix_code_locations", HERE / "fix_code_locations.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_fix_csv(path: Path) -> dict[tuple[str, str], dict]:
    rows: dict[tuple[str, str], dict] = {}
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            eid = (r.get("entry_id") or "").strip()
            fp = (r.get("field_path") or r.get("node_path") or "").strip()
            if not eid or not fp or fp == "*":
                continue
            rows[(eid, fp)] = r
    return rows


def classify_our_fix(row: dict) -> str:
    old = str(row.get("old_line") or "")
    new = str(row.get("new_line") or "")
    old_f = str(row.get("old_file") or "")
    new_f = str(row.get("new_file") or "")
    if old_f and new_f and old_f != new_f:
        return "file_changed"
    if old.isdigit() and "-" in new and new.split("-", 1)[0] == old:
        return "range_expand_same_start"
    if old != new:
        return "line_moved"
    return "other"


def parse_line(v: str | int) -> int | str:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    return int(s) if s.isdigit() else s


def apply_fix_to_entry(entry: dict, fixes: dict[tuple[str, str], dict], mod) -> dict:
    e = __import__("json").loads(__import__("json").dumps(entry))
    for path, node in mod.iter_nodes(e):
        r = fixes.get((e["entry_id"], path))
        if not r:
            continue
        if r.get("new_file"):
            node["file"] = r["new_file"]
        if r.get("new_line") not in (None, ""):
            node["line"] = parse_line(r["new_line"])
    return e
