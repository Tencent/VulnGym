#!/usr/bin/env python3
"""Conservative code-location repair for VulnGym issue #4.

See CONSTRAINTS.md before changing behavior.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENTRIES = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_CACHE = REPO_ROOT / ".repo_cache"
DEFAULT_OUT = Path(__file__).resolve().parent / "out"

PRIORITY_IDS = (
    "entry-00103",
    "entry-00320",
    "entry-00511",
    "entry-00185",
)

# Normalized code that is too uninformative to auto-trust even if it matches.
_DEGENERATE_EXACT = frozenset(
    {
        "}",
        "{",
        "};",
        "})",
        "});",
        "],",
        ")",
        "(",
        "];",
        "},",
    }
)


@dataclass
class LineSpan:
    start: int
    end: int

    @classmethod
    def parse(cls, line: int | str) -> LineSpan:
        if isinstance(line, int):
            if line < 1:
                raise ValueError(f"invalid line int: {line}")
            return cls(line, line)
        if isinstance(line, str) and re.fullmatch(r"\d+-\d+", line):
            a, b = map(int, line.split("-", 1))
            if not (1 <= a <= b):
                raise ValueError(f"invalid line range: {line}")
            return cls(a, b)
        raise ValueError(f"unsupported line value: {line!r}")

    def as_json(self) -> int | str:
        return self.start if self.start == self.end else f"{self.start}-{self.end}"


def normalize_code(s: str) -> str:
    """Loose compare: tabs/spaces collapse, strip each line, keep newlines."""
    lines = []
    for raw in s.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        collapsed = re.sub(r"[ \t]+", " ", raw.strip())
        lines.append(collapsed)
    # drop leading/trailing empty lines
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def repo_cache_dir(cache_root: Path, repo_url: str) -> Path:
    # https://github.com/org/name -> org__name
    parts = repo_url.rstrip("/").split("/")
    org, name = parts[-2], parts[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return cache_root / f"{org}__{name}"


def ensure_repo(repo_url: str, commit: str, cache_root: Path) -> Path:
    path = repo_cache_dir(cache_root, repo_url)
    if not (path / ".git").exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(path)],
            check=True,
        )
    # Windows: AutoGPT-like trees hit MAX_PATH without this.
    if sys.platform == "win32":
        subprocess.run(
            ["git", "config", "core.longpaths", "true"],
            cwd=path,
            check=False,
            capture_output=True,
        )
    # fetch commit if missing
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=path,
        capture_output=True,
    )
    if probe.returncode != 0:
        subprocess.run(
            ["git", "fetch", "--depth", "1", "origin", commit],
            cwd=path,
            check=True,
        )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if not head.startswith(commit[:12]):
        subprocess.run(["git", "checkout", "--force", commit], cwd=path, check=True)
    return path


def read_file_lines(repo_path: Path, rel: str) -> list[str] | None:
    p = repo_path / rel
    if not p.is_file():
        return None
    # try utf-8 then latin-1 fallback
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return p.read_text(encoding=enc).splitlines()
        except UnicodeDecodeError:
            continue
    return None


def extract_span(lines: list[str], span: LineSpan) -> str:
    chunk = lines[span.start - 1 : span.end]
    return "\n".join(chunk)


def codes_match(expected: str, actual: str) -> bool:
    return normalize_code(expected) == normalize_code(actual)


def is_degenerate_code(code: str) -> bool:
    n = normalize_code(code)
    if not n:
        return True
    if n in _DEGENERATE_EXACT:
        return True
    # single short token / brace-only
    if len(n) <= 2:
        return True
    return False


def find_unique_in_lines(
    lines: list[str], code: str, lo: int | None = None, hi: int | None = None
) -> LineSpan | None:
    """Find unique span matching normalized code within optional 1-based inclusive range."""
    needle = normalize_code(code)
    if not needle:
        return None
    needle_lines = needle.split("\n")
    n = len(needle_lines)
    start_i = (lo - 1) if lo else 0
    end_i = (hi) if hi else len(lines)  # exclusive when used as slice end for window start
    matches: list[LineSpan] = []
    # window start indices inclusive
    last_start = min(len(lines) - n, (hi - n) if hi else len(lines) - n)
    first_start = max(0, start_i)
    if last_start < first_start:
        return None
    for i in range(first_start, last_start + 1):
        window = "\n".join(lines[i : i + n])
        if normalize_code(window) == needle:
            matches.append(LineSpan(i + 1, i + n))
            if len(matches) > 1:
                return None
    return matches[0] if len(matches) == 1 else None


def list_repo_files(repo_path: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return [repo_path / rel for rel in out if rel]


@dataclass
class FixResult:
    status: str  # ok | fixed | needs_human
    reason: str
    old_file: str
    old_line: int | str
    new_file: str | None = None
    new_line: int | str | None = None
    strategy: str | None = None


def repair_node(
    repo_path: Path, node: dict[str, Any], *, allow_repo_wide: bool
) -> FixResult:
    file_ = node["file"]
    code = node["code"]
    try:
        span = LineSpan.parse(node["line"])
    except ValueError as e:
        return FixResult("needs_human", f"bad_line:{e}", file_, node["line"])

    if is_degenerate_code(code):
        return FixResult(
            "needs_human",
            "degenerate_snippet",
            file_,
            node["line"],
        )

    lines = read_file_lines(repo_path, file_)
    if lines is not None:
        actual = extract_span(lines, span)
        if codes_match(code, actual):
            return FixResult("ok", "already_matches", file_, node["line"])

        # 1) neighborhood ±5 around original span
        lo = max(1, span.start - 5)
        hi = min(len(lines), span.end + 5)
        hit = find_unique_in_lines(lines, code, lo, hi)
        if hit:
            return FixResult(
                "fixed",
                "neighborhood_pm5",
                file_,
                node["line"],
                file_,
                hit.as_json(),
                "neighborhood_pm5",
            )

        # 2) whole file
        hit = find_unique_in_lines(lines, code)
        if hit:
            return FixResult(
                "fixed",
                "whole_file",
                file_,
                node["line"],
                file_,
                hit.as_json(),
                "whole_file",
            )
    else:
        # missing file — fall through to repo-wide if allowed
        pass

    if not allow_repo_wide:
        return FixResult(
            "needs_human",
            "no_unique_match_in_file_or_missing_file",
            file_,
            node["line"],
        )

    # 3) repo-wide unique
    hits: list[tuple[str, LineSpan]] = []
    for path in list_repo_files(repo_path):
        try:
            text_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        hit = find_unique_in_lines(text_lines, code)
        if hit:
            rel = path.relative_to(repo_path).as_posix()
            hits.append((rel, hit))
            if len(hits) > 1:
                return FixResult(
                    "needs_human",
                    "repo_wide_ambiguous",
                    file_,
                    node["line"],
                )
    if len(hits) == 1:
        rel, hit = hits[0]
        return FixResult(
            "fixed",
            "repo_wide_unique",
            file_,
            node["line"],
            rel,
            hit.as_json(),
            "repo_wide_unique",
        )
    return FixResult(
        "needs_human",
        "repo_wide_no_match" if not hits else "repo_wide_ambiguous",
        file_,
        node["line"],
    )


def iter_nodes(entry: dict[str, Any]):
    yield "entry_point", entry["entry_point"]
    yield "critical_operation", entry["critical_operation"]
    for i, node in enumerate(entry.get("trace") or []):
        yield f"trace[{i}]", node


def load_entries(path: Path, only: set[str] | None) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if only and e["entry_id"] not in only:
                continue
            rows.append(e)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--entries", type=Path, default=DEFAULT_ENTRIES)
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="entry_id list; default for smoke = priority four",
    )
    ap.add_argument(
        "--priority",
        action="store_true",
        help="only the four issue-#4 priority entries",
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="process every entry in entries.jsonl",
    )
    ap.add_argument(
        "--repo-wide",
        action="store_true",
        help="enable stage-3 full-repo search (slower)",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="write entries.fixed.jsonl with fixes applied",
    )
    args = ap.parse_args()

    only: set[str] | None
    if args.all:
        only = None
    elif args.priority:
        only = set(PRIORITY_IDS)
    elif args.only is not None:
        only = set(args.only) if args.only else None
    else:
        only = set(PRIORITY_IDS)

    entries = load_entries(args.entries, only)
    args.out.mkdir(parents=True, exist_ok=True)

    fix_rows: list[dict[str, Any]] = []
    human_rows: list[dict[str, Any]] = []
    fixed_entries: list[dict[str, Any]] = []
    progress_path = args.out / "progress.jsonl"

    # resume: skip entry_ids already recorded as done
    done_ids: set[str] = set()
    if progress_path.is_file():
        with progress_path.open(encoding="utf-8") as pf:
            for line in pf:
                if not line.strip():
                    continue
                try:
                    done_ids.add(json.loads(line)["entry_id"])
                except (json.JSONDecodeError, KeyError):
                    continue

    total = len(entries)
    for idx, entry in enumerate(entries, start=1):
        eid = entry["entry_id"]
        if eid in done_ids:
            print(f"[{idx}/{total}] skip {eid} (resume)", flush=True)
            continue
        print(
            f"[{idx}/{total}] {eid} {entry['repo_url']}@{entry['commit'][:12]}",
            flush=True,
        )
        try:
            repo_path = ensure_repo(entry["repo_url"], entry["commit"], args.cache)
        except subprocess.CalledProcessError as e:
            human_rows.append(
                {
                    "entry_id": eid,
                    "field_path": "*",
                    "old_file": "",
                    "old_line": "",
                    "status": "needs_human",
                    "reason": f"repo_fetch_failed:{e}",
                    "strategy": "",
                }
            )
            with progress_path.open("a", encoding="utf-8") as pf:
                pf.write(
                    json.dumps(
                        {"entry_id": eid, "status": "fetch_failed"},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            continue

        new_entry = json.loads(json.dumps(entry))  # deep copy via JSON
        n_fix = n_human = 0
        for path_key, node in iter_nodes(new_entry):
            if path_key == "entry_point":
                target = new_entry["entry_point"]
            elif path_key == "critical_operation":
                target = new_entry["critical_operation"]
            else:
                tidx = int(path_key[path_key.find("[") + 1 : path_key.find("]")])
                target = new_entry["trace"][tidx]

            result = repair_node(repo_path, target, allow_repo_wide=args.repo_wide)
            base = {
                "entry_id": eid,
                "field_path": path_key,
                "old_file": result.old_file,
                "old_line": result.old_line,
                "status": result.status,
                "reason": result.reason,
                "strategy": result.strategy or "",
            }
            if result.status == "fixed":
                assert result.new_file is not None and result.new_line is not None
                target["file"] = result.new_file
                target["line"] = result.new_line
                base.update(
                    {"new_file": result.new_file, "new_line": result.new_line}
                )
                fix_rows.append(base)
                n_fix += 1
            elif result.status == "needs_human":
                human_rows.append(base)
                n_human += 1
        fixed_entries.append(new_entry)
        with progress_path.open("a", encoding="utf-8") as pf:
            pf.write(
                json.dumps(
                    {
                        "entry_id": eid,
                        "status": "done",
                        "fixed": n_fix,
                        "needs_human": n_human,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    # If resuming, also load previously written partial CSVs? Simpler: rewrite from
    # this run's in-memory rows only for entries processed this invocation, then
    # merge by re-scan would be better. For overnight first version: append-safe
    # rewrite of full CSVs from all processed in this process + warn on resume.
    # Better approach: always re-load ALL entries that are in done_ids and... too heavy.
    # Practical: write run-local CSVs; on resume, append to existing CSV bodies.
    fix_path = args.out / "fix_diff.csv"
    human_path = args.out / "needs_human.csv"
    fieldnames = [
        "entry_id",
        "field_path",
        "old_file",
        "old_line",
        "new_file",
        "new_line",
        "status",
        "reason",
        "strategy",
    ]

    def append_csv(path: Path, rows: list[dict[str, Any]]) -> None:
        new_file = not path.is_file()
        with path.open("a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if new_file:
                w.writeheader()
            for row in rows:
                w.writerow(row)

    append_csv(fix_path, fix_rows)
    append_csv(human_path, human_rows)

    if args.apply and fixed_entries:
        out_jsonl = args.out / "entries.fixed.partial.jsonl"
        with out_jsonl.open("a", encoding="utf-8") as f:
            for e in fixed_entries:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")

    print(
        f"this_run entries_processed={len(fixed_entries)} "
        f"fixed={len(fix_rows)} needs_human={len(human_rows)} out={args.out}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
