from __future__ import annotations

import argparse
from pathlib import Path

from .detect import scan_entries
from .io import (
    detect_jsonl_newline,
    file_sha256,
    load_jsonl,
    write_jsonl_atomic,
)
from .models import ApplyResult
from .policy import apply_decisions, decide_findings
from .report import build_summary, write_reports


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "entries.trace_fixed.jsonl"
DEFAULT_REPORTS = REPO_ROOT / "reports" / "trace_cleanup"


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Input entries JSONL (default: data/entries.jsonl).",
    )
    parser.add_argument(
        "--entry-id",
        action="append",
        default=[],
        help="Only scan this entry id; may be repeated.",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=DEFAULT_REPORTS,
        help="Report directory (default: reports/trace_cleanup).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed summary fields.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect and conservatively clean VulnGym trace structure.",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    check = subparsers.add_parser("check", help="Detect only; never write fixed JSONL.")
    _add_common_arguments(check)

    fix = subparsers.add_parser("fix", help="Apply explicitly enabled safe fixes.")
    _add_common_arguments(fix)
    fix.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Fixed JSONL output (must differ from input).",
    )
    fix.add_argument(
        "--duplicate-action",
        choices=("report", "remove-safe"),
        default="remove-safe",
    )
    fix.add_argument(
        "--order-action",
        choices=("report", "remove-definite"),
        default="report",
    )
    return parser


def _selected_entries(
    parser: argparse.ArgumentParser,
    entries: list[dict],
    requested: list[str],
) -> list[dict]:
    if not requested:
        return entries
    requested_set = set(requested)
    available = {entry["entry_id"] for entry in entries}
    missing = sorted(requested_set - available)
    if missing:
        parser.error(f"unknown --entry-id value(s): {', '.join(missing)}")
    return [entry for entry in entries if entry["entry_id"] in requested_set]


def _print_summary(summary: dict, verbose: bool) -> None:
    print(
        f"trace cleanup {summary['mode']}: "
        f"{summary['entries_scanned']} entries, "
        f"{summary['trace_nodes_scanned']} trace nodes, "
        f"{summary['auto_fixed']} fixes, "
        f"{summary['changed_entries']} changed entries"
    )
    if verbose:
        for key, value in summary.items():
            print(f"  {key}: {value}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    input_path = args.input.resolve()
    entries = load_jsonl(input_path)
    selected = _selected_entries(parser, entries, args.entry_id)
    detection = scan_entries(selected)

    duplicate_action = (
        args.duplicate_action if args.mode == "fix" else "report"
    )
    order_action = args.order_action if args.mode == "fix" else "report"
    decisions = decide_findings(
        detection.findings,
        mode=args.mode,
        duplicate_action=duplicate_action,
        order_action=order_action,
    )

    if args.mode == "fix":
        output_path = args.output.resolve()
        if output_path == input_path:
            parser.error("--output must differ from --input")
        application = apply_decisions(entries, decisions)
        write_jsonl_atomic(
            output_path,
            application.entries,
            newline=detect_jsonl_newline(input_path),
        )
        output_sha256 = file_sha256(output_path)
    else:
        application = ApplyResult(entries, 0, 0)
        output_sha256 = None

    summary = build_summary(
        detection,
        decisions,
        application,
        mode=args.mode,
        duplicate_action=duplicate_action,
        order_action=order_action,
        input_sha256=file_sha256(input_path),
        output_sha256=output_sha256,
    )
    write_reports(
        args.reports_dir.resolve(),
        decisions,
        summary,
        include_fix_log=args.mode == "fix",
    )
    _print_summary(summary, args.verbose)
    return 0
