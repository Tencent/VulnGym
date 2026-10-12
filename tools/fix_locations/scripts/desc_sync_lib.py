# -*- coding: utf-8 -*-
"""Mechanical desc line-anchor sync (no LLM). Shared by dry-run and apply."""
from __future__ import annotations

import re

# Explicit anchors only.
CN_LINE = re.compile(r"第\s*(\d+)\s*行")
CN_RANGE = re.compile(r"第\s*(\d+)\s*[–—\-−‐]\s*(\d+)\s*行")
EN_LINE = re.compile(r"\bline\s+(\d+)\b", re.I)
EN_RANGE = re.compile(r"\blines?\s+(\d+)\s*-\s*(\d+)\b", re.I)


def old_line_start(v) -> int | None:
    s = str(v)
    if s.isdigit():
        return int(s)
    if "-" in s:
        return int(s.split("-", 1)[0])
    return None


def new_line_parts(v) -> tuple[int, int] | None:
    s = str(v)
    if s.isdigit():
        n = int(s)
        return n, n
    if "-" in s:
        a, b = s.split("-", 1)
        return int(a), int(b)
    return None


def try_sync(desc: str, old_line, new_line) -> tuple[str | None, str]:
    """Return (new_desc or None, status)."""
    if not desc:
        return None, "no_desc"
    old_s = old_line_start(old_line)
    new_p = new_line_parts(new_line)
    if old_s is None or new_p is None:
        return None, "unparseable_line"
    new_a, new_b = new_p
    mentions = False
    for rx in (CN_LINE, EN_LINE):
        for m in rx.finditer(desc):
            if int(m.group(1)) == old_s:
                mentions = True
    for rx in (CN_RANGE, EN_RANGE):
        for m in rx.finditer(desc):
            if int(m.group(1)) == old_s:
                mentions = True
    if not mentions:
        return None, "no_anchor"

    def repl_cn_line(m):
        if int(m.group(1)) != old_s:
            return m.group(0)
        if new_a == new_b:
            return f"第 {new_a} 行"
        return f"第 {new_a}-{new_b} 行"

    def repl_en_line(m):
        if int(m.group(1)) != old_s:
            return m.group(0)
        if new_a == new_b:
            return f"line {new_a}"
        return f"lines {new_a}-{new_b}"

    out = CN_RANGE.sub(
        lambda m: (
            f"第 {new_a}-{new_b} 行" if int(m.group(1)) == old_s else m.group(0)
        ),
        desc,
    )
    out = CN_LINE.sub(repl_cn_line, out)
    out = EN_RANGE.sub(
        lambda m: (
            f"lines {new_a}-{new_b}" if int(m.group(1)) == old_s else m.group(0)
        ),
        out,
    )
    out = EN_LINE.sub(repl_en_line, out)
    if out == desc:
        return None, "anchor_but_unchanged"
    return out, "would_update"
