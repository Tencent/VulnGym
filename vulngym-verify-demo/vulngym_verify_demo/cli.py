# -*- coding: utf-8 -*-
"""CLI entry point: streamed JSONL input to streamed JSONL reports.

The CLI is deliberately the validation boundary: every non-blank input line
either reaches ``verify_entry`` after ``validate_entry`` succeeds, or produces
one stable ``__invalid_input__:<line_no>`` uncertain report. A bad line never
stops later lines from being processed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional, Tuple

from .agent import verify_entry
from .eval import evaluate, format_metrics, load_gold
from .llm_client import make_client, redact_text
from .schema import (
    build_invalid_input_report,
    build_report_validation_failure,
    validate_entry,
    validate_report,
)
from .tools import VulnGymTools, load_manifest, load_repo_catalog


try:  # Windows consoles otherwise often default to cp936.
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:  # pragma: no cover - not available for every stream type
    pass


JsonlRecord = Tuple[int, Optional[Any], Optional[str]]
_ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_SUPPORTED_ENV_KEYS = frozenset({"GLM_API_KEY", "GLM_BASE_URL", "GLM_MODEL"})


def iter_jsonl_records(path: Path, stats: Optional[dict] = None) -> Iterator[JsonlRecord]:
    """Yield ``(line_no, object, parse_error)`` for each non-blank JSONL row."""
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                if stats is not None:
                    stats["blank_lines"] = stats.get("blank_lines", 0) + 1
                continue
            try:
                yield line_no, json.loads(text), None
            except json.JSONDecodeError as exc:
                yield line_no, None, redact_text(str(exc))


def iter_jsonl(path: Path) -> Iterable[dict]:
    """Backward-compatible iterator used by older callers and tests."""
    for line_no, item, error in iter_jsonl_records(path):
        if error is not None:
            yield {
                "__parse_error__": True,
                "__line_no__": line_no,
                "__error_message__": error,
            }
        else:
            yield item


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    """Write report rows as UTF-8 JSONL (kept as public compatibility helper)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def expand_path(value: str) -> Path:
    """Expand ``~``, POSIX ``$VAR`` and Windows ``%VAR%`` into an absolute path."""
    return Path(os.path.expanduser(os.path.expandvars(value))).resolve()


def load_provider_env_file(path: Path) -> None:
    """Load explicit, provider-only settings without overwriting process env.

    The CLI never auto-loads a secret file: callers must opt in with
    ``--env-file``.  This keeps CI and tests independent of a developer's
    local credentials while allowing an ignored ``.env`` file for local runs.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"env file line {line_no}: expected KEY=VALUE")
            key, value = (part.strip() for part in line.split("=", 1))
            if not _ENV_KEY_RE.fullmatch(key):
                raise ValueError(f"env file line {line_no}: invalid variable name")
            if key not in _SUPPORTED_ENV_KEYS:
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            if not value:
                raise ValueError(f"env file line {line_no}: {key} must not be empty")
            os.environ.setdefault(key, value)


def _safe_text(value: Any) -> str:
    return redact_text(str(value))


def _schema_error_kind(errors: List[str]) -> str:
    if any("forbidden field" in error for error in errors):
        return "forbidden_field"
    if any("missing required field" in error for error in errors):
        return "missing_field"
    return "schema_violation"


def _print_summary(summary_rows: List[Tuple[str, str, str, str]]) -> None:
    counts = Counter(row[2] for row in summary_rows)
    print()
    print("=" * 72)
    print(f"VulnGym 字段级验证 — 总览 (n={len(summary_rows)})")
    print(f"  correct   : {counts.get('correct', 0)}")
    print(f"  incorrect : {counts.get('incorrect', 0)}")
    print(f"  uncertain : {counts.get('uncertain', 0)}")
    print("-" * 72)
    print(f"{'entry_id':<24} {'report_id':<24} {'verdict':<10} summary")
    print("-" * 72)
    for entry_id, report_id, verdict, summary in summary_rows:
        print(f"{_safe_text(entry_id):<24} {_safe_text(report_id):<24} {verdict:<10} {_safe_text(summary)}")
    print("=" * 72)


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--entries", required=True, help="entries.jsonl 路径")
    parser.add_argument("--repo-cache", required=True, help="本地仓库快照缓存根目录")
    parser.add_argument("--advisories", required=True, help="本地公告缓存目录")
    parser.add_argument("--out", default="out/reports.jsonl", help="输出报告 JSONL")
    parser.add_argument("--manifest", default=None, help="可选 snapshot manifest.json 路径")
    parser.add_argument("--repo-catalog", default=None, help="可选本地 Git clone catalog.json 路径")
    parser.add_argument(
        "--env-file", default=None,
        help="可选 provider 环境文件；仅加载 GLM_API_KEY/GLM_BASE_URL/GLM_MODEL，且不覆盖当前环境变量",
    )
    parser.add_argument(
        "--llm", default="auto", choices=["auto", "qwen", "glm", "deepseek", "mock"],
        help="LLM 后端；auto 在无可用 key 时安全降级为 uncertain",
    )
    parser.add_argument("--verbose", action="store_true", help="打印每条 entry 的规划与字段判定")
    parser.add_argument("--llm-timeout", type=float, default=30.0, help="真实 LLM 请求超时秒数（默认：30）")
    parser.add_argument("--gold", default=None, help="可选 gold.jsonl，用于输出评测指标")
    parser.add_argument("--bench", action="store_true", help="等价于 --gold mock_data/gold.jsonl")


def _load_configuration(args: argparse.Namespace) -> Tuple[Path, Path, Path, Path, Optional[Path], Optional[Path]]:
    if args.bench and not args.gold:
        args.gold = "mock_data/gold.jsonl"
    entries_path = expand_path(args.entries)
    repo_cache = expand_path(args.repo_cache)
    advisory_dir = expand_path(args.advisories)
    out_path = expand_path(args.out)
    manifest_path = expand_path(args.manifest) if args.manifest else None
    catalog_path = expand_path(args.repo_catalog) if args.repo_catalog else None
    return entries_path, repo_cache, advisory_dir, out_path, manifest_path, catalog_path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="VulnGym 字段级验证 Demo")
    _add_arguments(parser)
    args = parser.parse_args(argv)

    try:
        if args.env_file:
            env_path = expand_path(args.env_file)
            if not env_path.is_file():
                raise ValueError("env file not found")
            load_provider_env_file(env_path)
        entries_path, repo_cache, advisory_dir, out_path, manifest_path, catalog_path = _load_configuration(args)
        if not entries_path.is_file():
            raise ValueError("entries file not found")
        if not repo_cache.is_dir():
            raise ValueError("repo-cache directory not found")
        if not advisory_dir.is_dir():
            raise ValueError("advisories directory not found")
        if manifest_path is not None and not manifest_path.is_file():
            raise ValueError("manifest file not found")
        if catalog_path is not None and not catalog_path.is_file():
            raise ValueError("repo-catalog file not found")
        if args.gold and not expand_path(args.gold).is_file():
            raise ValueError("gold file not found")
        if args.llm_timeout <= 0:
            raise ValueError("llm-timeout must be greater than zero")

        manifest = load_manifest(manifest_path) if manifest_path else None
        repo_catalog = load_repo_catalog(catalog_path) if catalog_path else None
        gold = load_gold(expand_path(args.gold)) if args.gold else None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] configuration error: {_safe_text(exc)}", file=sys.stderr)
        return 2

    try:
        tools = VulnGymTools(
            repo_cache_dir=repo_cache,
            advisory_dir=advisory_dir,
            manifest=manifest,
            repo_catalog=repo_catalog,
        )
        llm = make_client(args.llm, timeout=args.llm_timeout)
    except Exception as exc:  # configuration/provider initialization is unrecoverable
        print(f"[ERROR] initialization error: {_safe_text(exc)}", file=sys.stderr)
        return 2

    print(f"[load] streaming entries from {_safe_text(entries_path)}")
    print(f"[llm] using {type(llm).__name__}")
    summary_rows: List[Tuple[str, str, str, str]] = []
    reports_for_eval: Optional[List[dict]] = [] if gold is not None else None
    rows_processed = 0
    invalid_rows = 0
    input_stats = {"blank_lines": 0}

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as output:
            for line_no, entry, parse_error in iter_jsonl_records(entries_path, input_stats):
                rows_processed += 1
                if parse_error is not None:
                    report = build_invalid_input_report(line_no, "json_parse_error", parse_error)
                    invalid_rows += 1
                else:
                    errors = validate_entry(entry)
                    if errors:
                        report = build_invalid_input_report(
                            line_no, _schema_error_kind(errors), _safe_text("; ".join(errors)),
                        )
                        invalid_rows += 1
                    else:
                        try:
                            report = verify_entry(entry, tools, llm, verbose=args.verbose)
                        except Exception as exc:  # keep later valid rows running
                            report = build_invalid_input_report(
                                line_no, "processing_error", _safe_text(type(exc).__name__),
                            )
                            invalid_rows += 1
                report_errors = validate_report(report)
                if report_errors:
                    report = build_report_validation_failure(entry, line_no, report_errors)
                output.write(json.dumps(report, ensure_ascii=False) + "\n")
                summary_rows.append((
                    str(report.get("entry_id", "")), str(report.get("report_id", "")),
                    str(report.get("verdict", "uncertain")), str(report.get("summary", "")),
                ))
                if reports_for_eval is not None:
                    reports_for_eval.append(report)
    except (OSError, UnicodeError) as exc:
        print(f"[ERROR] I/O error: {_safe_text(exc)}", file=sys.stderr)
        return 2

    print(
        f"[save] wrote {rows_processed} reports to {_safe_text(out_path)} "
        f"({invalid_rows} invalid input rows; {input_stats['blank_lines']} blank lines skipped)"
    )
    _print_summary(summary_rows)
    if gold is not None and reports_for_eval is not None:
        print()
        print(format_metrics(evaluate(reports_for_eval, gold)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
