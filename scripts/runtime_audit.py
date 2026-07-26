#!/usr/bin/env python3
"""Runtime audit against the GitHub raw view of each target's commit.

Verifies the SCHEMA.md acceptance criterion "every repaired {file, line,
code} triple matches the upstream commit" by fetching each entry's file
at the listed commit and running H1-H5 checks. All events are emitted as
NDJSON to `debug-b5f720.log`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRIES_PATH = REPO_ROOT / "data" / "entries.jsonl"
LOG_PATH = REPO_ROOT / "debug-b5f720.log"
# Trace-fix + config-vuln rounds (see main() boot record for the split).
TARGETED = (
    "entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391",
    "entry-00241", "entry-00242", "entry-00243", "entry-00244",
)
TIMEOUT = 30


def log_payload(
    *,
    run_id: str,
    hypothesis_id: str,
    location: str,
    message: str,
    data: dict[str, Any],
) -> None:
    payload = {
        "id": f"log_{int(time.time() * 1000)}",
        "timestamp": int(time.time() * 1000),
        "location": location,
        "message": message,
        "data": {**data, "runId": run_id, "hypothesisId": hypothesis_id},
    }
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def raw_url(repo_url: str, commit: str, rel_path: str) -> str:
    parts = repo_url.rstrip("/").split("/")
    org, repo = parts[-2], parts[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://raw.githubusercontent.com/{org}/{repo}/{commit}/{rel_path.lstrip('/')}"


def fetch_remote(url: str) -> tuple[int, str | None]:
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError) as exc:
        return 0, str(exc)


def fetch_lines_remote(repo_url: str, commit: str, rel_path: str, start: int, end: int) -> list[str] | None:
    status, body = fetch_remote(raw_url(repo_url, commit, rel_path))
    if status != 200 or body is None:
        return None
    lines = body.splitlines()
    if start < 1 or end > len(lines) or start > end:
        return None
    return lines[start - 1 : end]


def parse_line(line: int | str) -> tuple[int, int]:
    if isinstance(line, int):
        return line, line
    if isinstance(line, str) and "-" in line:
        a, b = line.split("-", 1)
        return int(a), int(b)
    raise ValueError(f"bad line field: {line!r}")


def check_h1(entry: dict, repo_url: str, commit: str, run_id: str) -> list[dict]:
    failures = []
    for label, node in (
        ("entry_point", entry["entry_point"]),
        ("critical_operation", entry["critical_operation"]),
    ):
        rel_path = node["file"]
        line_field = node["line"]
        try:
            start, end = parse_line(line_field)
        except ValueError as exc:
            failures.append({"label": label, "kind": "bad_line_field", "error": str(exc)})
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:{label}",
                message=f"{entry['entry_id']}: bad line field",
                data={"entry_id": entry["entry_id"], "line_field": line_field},
            )
            continue

        upstream = fetch_lines_remote(repo_url, commit, rel_path, start, end)
        if upstream is None:
            failures.append(
                {
                    "label": label,
                    "kind": "file_or_range_unavailable",
                    "range": [start, end],
                    "file": rel_path,
                }
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:{label}",
                message=f"{entry['entry_id']}: file/range unavailable",
                data={"entry_id": entry["entry_id"], "file": rel_path, "range": [start, end]},
            )
            continue

        claimed = node["code"].splitlines()
        if len(claimed) != len(upstream):
            failures.append(
                {
                    "label": label,
                    "kind": "line_count_mismatch",
                    "claimed_lines": len(claimed),
                    "upstream_lines": len(upstream),
                    "range": [start, end],
                }
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:{label}",
                message=f"{entry['entry_id']}: line count mismatch",
                data={
                    "entry_id": entry["entry_id"],
                    "file": rel_path,
                    "range": [start, end],
                    "claimed_lines": len(claimed),
                    "upstream_lines": len(upstream),
                },
            )
            continue

        mismatches = []
        for offset, (c, u) in enumerate(zip(claimed, upstream)):
            if c != u:
                mismatches.append(
                    {"offset": offset, "claimed": c, "upstream": u, "abs_line": start + offset}
                )
        if mismatches:
            failures.append(
                {"label": label, "kind": "code_mismatch", "mismatches": mismatches[:3]}
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:{label}",
                message=f"{entry['entry_id']}: code mismatch at {rel_path} L{start}-{end}",
                data={
                    "entry_id": entry["entry_id"],
                    "file": rel_path,
                    "range": [start, end],
                    "mismatches": mismatches[:3],
                },
            )
        else:
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:{label}",
                message=f"{entry['entry_id']}: {label} matched {rel_path} L{start}-{end}",
                data={"entry_id": entry["entry_id"], "range": [start, end]},
            )

    for idx, node in enumerate(entry.get("trace", [])):
        label = f"trace[{idx}]"
        rel_path = node["file"]
        try:
            start, end = parse_line(node["line"])
        except ValueError as exc:
            failures.append({"label": label, "kind": "bad_line_field", "error": str(exc)})
            continue

        upstream = fetch_lines_remote(repo_url, commit, rel_path, start, end)
        if upstream is None:
            failures.append(
                {
                    "label": label,
                    "kind": "file_or_range_unavailable",
                    "range": [start, end],
                    "file": rel_path,
                }
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:trace[{idx}]",
                message=f"{entry['entry_id']}: trace[{idx}] file/range unavailable",
                data={"entry_id": entry["entry_id"], "file": rel_path, "range": [start, end]},
            )
            continue

        claimed = node["code"].splitlines()
        if len(claimed) != len(upstream):
            failures.append(
                {
                    "label": label,
                    "kind": "line_count_mismatch",
                    "claimed_lines": len(claimed),
                    "upstream_lines": len(upstream),
                    "range": [start, end],
                }
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:trace[{idx}]",
                message=f"{entry['entry_id']}: trace[{idx}] line count mismatch",
                data={
                    "entry_id": entry["entry_id"],
                    "file": rel_path,
                    "range": [start, end],
                    "claimed_lines": len(claimed),
                    "upstream_lines": len(upstream),
                },
            )
            continue

        mismatches = []
        for offset, (c, u) in enumerate(zip(claimed, upstream)):
            if c != u:
                mismatches.append(
                    {"offset": offset, "claimed": c, "upstream": u, "abs_line": start + offset}
                )
        if mismatches:
            failures.append(
                {"label": label, "kind": "code_mismatch", "mismatches": mismatches[:3]}
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:trace[{idx}]",
                message=f"{entry['entry_id']}: trace[{idx}] code mismatch",
                data={
                    "entry_id": entry["entry_id"],
                    "file": rel_path,
                    "range": [start, end],
                    "mismatches": mismatches[:3],
                },
            )
        else:
            log_payload(
                run_id=run_id,
                hypothesis_id="H1",
                location=f"scripts/runtime_audit.py:trace[{idx}]",
                message=f"{entry['entry_id']}: trace[{idx}] matched",
                data={"entry_id": entry["entry_id"], "file": rel_path, "range": [start, end]},
            )
    return failures


def check_h2(entry: dict, repo_url: str, commit: str, run_id: str) -> list[dict]:
    failures = []
    seen: set[str] = set()
    for label, node in (
        ("entry_point", entry["entry_point"]),
        ("critical_operation", entry["critical_operation"]),
        *((f"trace[{i}]", n) for i, n in enumerate(entry.get("trace", []))),
    ):
        rel_path = node["file"]
        if rel_path in seen:
            continue
        seen.add(rel_path)
        status, _body = fetch_remote(raw_url(repo_url, commit, rel_path))
        if status != 200:
            failures.append(
                {"label": label, "kind": "file_missing_at_commit", "file": rel_path, "status": status}
            )
            log_payload(
                run_id=run_id,
                hypothesis_id="H2",
                location="scripts/runtime_audit.py:H2",
                message=f"{entry['entry_id']}: file missing at commit",
                data={"entry_id": entry["entry_id"], "file": rel_path, "status": status},
            )
        else:
            log_payload(
                run_id=run_id,
                hypothesis_id="H2",
                location="scripts/runtime_audit.py:H2",
                message=f"{entry['entry_id']}: file exists",
                data={"entry_id": entry["entry_id"], "file": rel_path, "status": status},
            )
    return failures


def check_h3(entry: dict, run_id: str) -> list[dict]:
    failures = []

    def check_node(node: dict[str, Any]) -> list[str]:
        errs = []
        for required_key in ("file", "line", "code"):
            if not node.get(required_key):
                errs.append(f"missing {required_key}")
        line_value = node.get("line")
        if line_value is not None:
            if isinstance(line_value, int):
                if line_value < 1:
                    errs.append("line < 1")
            elif isinstance(line_value, str):
                if not re.match(r"^\d+-\d+$", line_value):
                    errs.append("line not in 'a-b' format")
                else:
                    a, b = line_value.split("-")
                    if int(a) > int(b):
                        errs.append("line range a>b")
                    if int(a) < 1:
                        errs.append("line range a<1")
            else:
                errs.append("line wrong type")
        if not node.get("code", "").strip():
            errs.append("empty code")
        return errs

    errs = check_node(entry["entry_point"])
    if errs:
        failures.append({"label": "entry_point", "errors": errs})

    errs = check_node(entry["critical_operation"])
    if errs:
        failures.append({"label": "critical_operation", "errors": errs})

    if not entry.get("trace"):
        failures.append({"label": "trace", "errors": ["empty"]})
    for i, n in enumerate(entry.get("trace", [])):
        errs = check_node(n)
        if errs:
            failures.append({"label": f"trace[{i}]", "errors": errs})
    if not (entry.get("verify") in (0, 1)):
        failures.append({"label": "verify", "errors": [f"got {entry.get('verify')}"]})

    if failures:
        log_payload(
            run_id=run_id,
            hypothesis_id="H3",
            location="scripts/runtime_audit.py:H3",
            message=f"{entry['entry_id']}: schema violations",
            data={"entry_id": entry["entry_id"], "violations": failures},
        )
    else:
        log_payload(
            run_id=run_id,
            hypothesis_id="H3",
            location="scripts/runtime_audit.py:H3",
            message=f"{entry['entry_id']}: schema clean",
            data={"entry_id": entry["entry_id"]},
        )
    return failures


NOISE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*\}\s*$"),
    re.compile(r"^\s*\]\s*[,;]?\s*$"),
    re.compile(r"^\s*default:\s*[^,]+,?\s*$"),
    re.compile(r"^\s*return\s+(true|false)\s*;\s*$"),
)


def check_h4(entry: dict, run_id: str) -> list[dict]:
    bad = []
    for i, n in enumerate(entry.get("trace", [])):
        code = n.get("code", "").strip()
        if any(p.match(line) for line in code.splitlines() for p in NOISE_PATTERNS):
            lines = code.splitlines()
            if len(lines) <= 1:
                bad.append({"trace_index": i, "code": code, "file": n["file"]})
                log_payload(
                    run_id=run_id,
                    hypothesis_id="H4",
                    location="scripts/runtime_audit.py:H4",
                    message=f"{entry['entry_id']}: noisy trace node",
                    data={"entry_id": entry["entry_id"], "trace_index": i, "code": code},
                )
            else:
                log_payload(
                    run_id=run_id,
                    hypothesis_id="H4",
                    location="scripts/runtime_audit.py:H4",
                    message=f"{entry['entry_id']}: multi-line trace allows pattern",
                    data={"entry_id": entry["entry_id"], "trace_index": i},
                )
    return bad


def check_h5(entry: dict, run_id: str) -> list[dict]:
    type_counts = {"int": 0, "range": 0}
    for n in (
        entry["entry_point"],
        entry["critical_operation"],
        *entry.get("trace", []),
    ):
        if isinstance(n["line"], int):
            type_counts["int"] += 1
        elif isinstance(n["line"], str):
            type_counts["range"] += 1
    log_payload(
        run_id=run_id,
        hypothesis_id="H5",
        location="scripts/runtime_audit.py:H5",
        message=f"{entry['entry_id']}: line field form distribution",
        data={"entry_id": entry["entry_id"], "counts": type_counts},
    )
    return []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--use-remote", action="store_true")
    args = parser.parse_args(argv)

    if LOG_PATH.exists():
        LOG_PATH.unlink()

    log_payload(
        run_id="initial",
        hypothesis_id="boot",
        location="scripts/runtime_audit.py:main",
        message="audit start",
        data={
            "targeted": list(TARGETED),
            "use_remote": args.use_remote,
            "rounds": {
                "trace_fix": ["entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391"],
                "config_vuln": ["entry-00241", "entry-00242", "entry-00243", "entry-00244"],
            },
        },
    )

    found: dict[str, dict] = {}
    with ENTRIES_PATH.open("r", encoding="utf-8") as src:
        for line_no, raw in enumerate(src, start=1):
            line = raw.strip()
            if not line:
                print(f"{ENTRIES_PATH}: blank JSONL row at line {line_no}", file=sys.stderr)
                return 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"{ENTRIES_PATH}: invalid JSON at line {line_no}: {exc}", file=sys.stderr)
                return 1
            if obj.get("entry_id") in TARGETED:
                found[obj["entry_id"]] = obj

    summary: dict[str, dict] = {}
    overall_failures = 0

    for eid in TARGETED:
        entry = found.get(eid)
        if entry is None:
            log_payload(
                run_id="initial",
                hypothesis_id="boot",
                location="scripts/runtime_audit.py:main",
                message=f"missing target {eid}",
                data={"entry_id": eid},
            )
            overall_failures += 1
            continue

        run_id = "initial"
        repo_url = entry["repo_url"]
        commit = entry["commit"]

        h1 = check_h1(entry, repo_url, commit, run_id)
        h2 = check_h2(entry, repo_url, commit, run_id)
        h3 = check_h3(entry, run_id)
        h4 = check_h4(entry, run_id)
        h5 = check_h5(entry, run_id)

        summary[eid] = {
            "h1_code_matches_failures": len(h1),
            "h2_file_exists_failures": len(h2),
            "h3_schema_failures": len(h3),
            "h4_trace_noise_failures": len(h4),
            "h5_line_form_recorded": True,
            "failures_detail": {"h1": h1, "h2": h2, "h3": h3, "h4": h4},
        }
        overall_failures += len(h1) + len(h2) + len(h3) + len(h4)

    log_payload(
        run_id="initial",
        hypothesis_id="summary",
        location="scripts/runtime_audit.py:main",
        message="audit summary",
        data={"summary": summary, "overall_failures": overall_failures},
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if overall_failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
