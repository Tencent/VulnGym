#!/usr/bin/env python3
"""Validate VulnGym JSONL files against the documented dataset contract."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENTRIES = REPO_ROOT / "data" / "entries.jsonl"
DEFAULT_REPORTS = REPO_ROOT / "data" / "reports.jsonl"
EXPECTED_ORIGIN = "GitHub Advisory Database (reviewed)"

ENTRY_REQUIRED_FIELDS = {
    "commit",
    "critical_operation",
    "entry_id",
    "entry_point",
    "origin",
    "project",
    "repo_url",
    "report_id",
    "source_link",
    "trace",
    "verify",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_ids",
    "vuln_title",
}
REPORT_REQUIRED_FIELDS = {
    "commit",
    "entry_ids",
    "num_entries",
    "origin",
    "project",
    "repo_url",
    "report_id",
    "source_link",
    "vuln_ids",
    "vuln_title",
}
NODE_REQUIRED_FIELDS = {"file", "line", "code"}
FORBIDDEN_ENTRY_FIELDS = {
    "annotated_by",
    "created_at",
    "description",
    "detection_type",
    "generality",
    "ground_truth",
    "human_remark",
    "is_active",
    "pipeline_id",
    "taint_sink",
    "taint_source",
    "vuln_category_l3",
}

ENTRY_ID_RE = re.compile(r"^entry-\d{5}$")
REPORT_ID_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
LINE_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")
WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[/\\]")
CJK_QUESTION_RE = re.compile(
    r"(?:[\u3400-\u4dbf\u4e00-\u9fff]\?|\?[\u3400-\u4dbf\u4e00-\u9fff])"
)
MOJIBAKE_MARKERS = ("\ufffd", "\u951f\u65a4\u62f7")


@dataclass(frozen=True)
class LoadedRow:
    line: int
    data: dict[str, Any]


@dataclass(frozen=True)
class Diagnostic:
    code: str
    file: str
    line: int | None
    path: str
    message: str

    def render(self) -> str:
        location = self.file if self.line is None else f"{self.file}:{self.line}"
        if self.path:
            location = f"{location}:{self.path}"
        return f"{location}: [{self.code}] {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "file": self.file,
            "line": self.line,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class ValidationResult:
    diagnostics: tuple[Diagnostic, ...]
    stats: dict[str, int]

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "stats": self.stats,
            "errors": [item.to_dict() for item in self.diagnostics],
        }


def add_error(
    diagnostics: list[Diagnostic],
    code: str,
    file: Path,
    line: int | None,
    path: str,
    message: str,
) -> None:
    diagnostics.append(
        Diagnostic(
            code=code,
            file=str(file),
            line=line,
            path=path,
            message=message,
        )
    )


def load_jsonl(path: Path, diagnostics: list[Diagnostic]) -> list[LoadedRow]:
    rows: list[LoadedRow] = []
    try:
        raw = path.read_bytes()
    except OSError as exc:
        add_error(diagnostics, "FILE_READ", path, None, "", str(exc))
        return rows

    if raw and not raw.endswith(b"\n"):
        add_error(
            diagnostics,
            "FILE_FINAL_NEWLINE",
            path,
            None,
            "",
            "JSONL file must end with a newline",
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        add_error(diagnostics, "FILE_UTF8", path, None, "", str(exc))
        return rows

    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            add_error(
                diagnostics,
                "JSONL_BLANK_LINE",
                path,
                line_number,
                "",
                "blank lines are not part of the JSONL contract",
            )
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            add_error(
                diagnostics,
                "JSON_INVALID",
                path,
                line_number,
                "",
                f"invalid JSON: {exc.msg} at column {exc.colno}",
            )
            continue
        if not isinstance(value, dict):
            add_error(
                diagnostics,
                "ROW_NOT_OBJECT",
                path,
                line_number,
                "",
                "each JSONL row must be an object",
            )
            continue
        rows.append(LoadedRow(line_number, value))
    return rows


def validate_text(
    value: Any,
    diagnostics: list[Diagnostic],
    file: Path,
    line: int,
    path: str,
    *,
    allow_empty: bool = False,
    check_question_marks: bool = False,
) -> bool:
    if not isinstance(value, str):
        add_error(
            diagnostics,
            "TEXT_TYPE",
            file,
            line,
            path,
            "value must be a string",
        )
        return False
    if not allow_empty and not value.strip():
        add_error(
            diagnostics,
            "TEXT_EMPTY",
            file,
            line,
            path,
            "value must not be empty",
        )
    if any(marker in value for marker in MOJIBAKE_MARKERS):
        add_error(
            diagnostics,
            "TEXT_CORRUPTION_MARKER",
            file,
            line,
            path,
            "text contains a replacement or mojibake marker",
        )
    if check_question_marks and CJK_QUESTION_RE.search(value):
        add_error(
            diagnostics,
            "TEXT_SUSPICIOUS_QUESTION_MARK",
            file,
            line,
            path,
            "ASCII '?' adjacent to CJK text may indicate encoding damage",
        )
    return True


def validate_line_value(
    value: Any,
    diagnostics: list[Diagnostic],
    file: Path,
    line: int,
    path: str,
) -> str | None:
    if isinstance(value, bool):
        add_error(
            diagnostics,
            "NODE_LINE_INVALID",
            file,
            line,
            path,
            "line must be a positive integer or a start-end range",
        )
        return None
    if isinstance(value, int):
        if value >= 1:
            return "integer"
    elif isinstance(value, str):
        match = LINE_RANGE_RE.fullmatch(value)
        if match and int(match.group(1)) <= int(match.group(2)):
            return "range"
    add_error(
        diagnostics,
        "NODE_LINE_INVALID",
        file,
        line,
        path,
        "line must be a positive integer or a start-end range with start <= end",
    )
    return None


def validate_node(
    node: Any,
    diagnostics: list[Diagnostic],
    file: Path,
    line: int,
    path: str,
    line_counts: Counter[str],
) -> None:
    if not isinstance(node, dict):
        add_error(
            diagnostics,
            "NODE_NOT_OBJECT",
            file,
            line,
            path,
            "node must be an object",
        )
        return

    missing = sorted(NODE_REQUIRED_FIELDS - node.keys())
    if missing:
        add_error(
            diagnostics,
            "NODE_REQUIRED_FIELDS",
            file,
            line,
            path,
            f"missing required fields: {', '.join(missing)}",
        )

    if "file" in node and validate_text(
        node["file"], diagnostics, file, line, f"{path}.file"
    ):
        node_file = node["file"].replace("\\", "/")
        if (
            node_file.startswith("/")
            or WINDOWS_ABSOLUTE_RE.match(node["file"])
            or ".." in node_file.split("/")
        ):
            add_error(
                diagnostics,
                "NODE_FILE_NOT_RELATIVE",
                file,
                line,
                f"{path}.file",
                "file must be a repository-relative path without '..' segments",
            )

    if "line" in node:
        line_kind = validate_line_value(
            node["line"], diagnostics, file, line, f"{path}.line"
        )
        if line_kind:
            line_counts[line_kind] += 1

    if "code" in node:
        validate_text(
            node["code"],
            diagnostics,
            file,
            line,
            f"{path}.code",
            allow_empty=True,
        )
    if "desc" in node:
        validate_text(
            node["desc"],
            diagnostics,
            file,
            line,
            f"{path}.desc",
            allow_empty=False,
            check_question_marks=True,
        )


def validate_common_record_fields(
    data: dict[str, Any],
    diagnostics: list[Diagnostic],
    file: Path,
    line: int,
) -> None:
    report_id = data.get("report_id")
    if not isinstance(report_id, str) or not REPORT_ID_RE.fullmatch(report_id):
        add_error(
            diagnostics,
            "REPORT_ID_FORMAT",
            file,
            line,
            "report_id",
            "report_id must use the GHSA-XXXX-XXXX-XXXX format",
        )

    source_link = data.get("source_link")
    if validate_text(source_link, diagnostics, file, line, "source_link"):
        expected_suffix = str(report_id).lower()
        if (
            not source_link.startswith("https://github.com/advisories/")
            or source_link.rstrip("/").rsplit("/", 1)[-1].lower() != expected_suffix
        ):
            add_error(
                diagnostics,
                "SOURCE_LINK_MISMATCH",
                file,
                line,
                "source_link",
                "source_link must point to the row's report_id",
            )

    commit = data.get("commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        add_error(
            diagnostics,
            "COMMIT_FORMAT",
            file,
            line,
            "commit",
            "commit must be a 40-character lowercase hexadecimal SHA",
        )

    repo_url = data.get("repo_url")
    if not isinstance(repo_url, str) or not repo_url.startswith("https://github.com/"):
        add_error(
            diagnostics,
            "REPO_URL_FORMAT",
            file,
            line,
            "repo_url",
            "repo_url must start with https://github.com/",
        )

    if data.get("origin") != EXPECTED_ORIGIN:
        add_error(
            diagnostics,
            "ORIGIN_VALUE",
            file,
            line,
            "origin",
            f"origin must equal {EXPECTED_ORIGIN!r}",
        )

    vuln_ids = data.get("vuln_ids")
    if not isinstance(vuln_ids, list) or not all(
        isinstance(item, str) for item in vuln_ids
    ):
        add_error(
            diagnostics,
            "VULN_IDS_TYPE",
            file,
            line,
            "vuln_ids",
            "vuln_ids must be a list of strings",
        )
    else:
        if len(vuln_ids) != len(set(vuln_ids)):
            add_error(
                diagnostics,
                "VULN_IDS_DUPLICATE",
                file,
                line,
                "vuln_ids",
                "vuln_ids must not contain duplicates",
            )
        if any(item != item.upper() for item in vuln_ids):
            add_error(
                diagnostics,
                "VULN_IDS_CASE",
                file,
                line,
                "vuln_ids",
                "vuln_ids must be upper-case",
            )
    for field in ("project", "vuln_title"):
        if field in data:
            validate_text(
                data[field],
                diagnostics,
                file,
                line,
                field,
                check_question_marks=True,
            )


def validate_entry_rows(
    rows: list[LoadedRow],
    file: Path,
    diagnostics: list[Diagnostic],
    line_counts: Counter[str],
) -> None:
    for row in rows:
        data = row.data
        if list(data) != sorted(data):
            add_error(
                diagnostics,
                "ROW_FIELD_ORDER",
                file,
                row.line,
                "",
                "top-level fields must be sorted alphabetically",
            )
        missing = sorted(ENTRY_REQUIRED_FIELDS - data.keys())
        if missing:
            add_error(
                diagnostics,
                "ENTRY_REQUIRED_FIELDS",
                file,
                row.line,
                "",
                f"missing required fields: {', '.join(missing)}",
            )
        forbidden = sorted(FORBIDDEN_ENTRY_FIELDS & data.keys())
        if forbidden:
            add_error(
                diagnostics,
                "ENTRY_FORBIDDEN_FIELDS",
                file,
                row.line,
                "",
                f"internal fields must be omitted: {', '.join(forbidden)}",
            )

        entry_id = data.get("entry_id")
        if not isinstance(entry_id, str) or not ENTRY_ID_RE.fullmatch(entry_id):
            add_error(
                diagnostics,
                "ENTRY_ID_FORMAT",
                file,
                row.line,
                "entry_id",
                "entry_id must use the entry-00000 format",
            )
        validate_common_record_fields(data, diagnostics, file, row.line)

        verify = data.get("verify")
        if isinstance(verify, bool) or verify not in (0, 1):
            add_error(
                diagnostics,
                "VERIFY_VALUE",
                file,
                row.line,
                "verify",
                "verify must be the integer 0 or 1",
            )

        for field in ("vuln_category_l1", "vuln_category_l2"):
            if field in data:
                validate_text(
                    data[field],
                    diagnostics,
                    file,
                    row.line,
                    field,
                    check_question_marks=True,
                )

        if "entry_point" in data:
            validate_node(
                data["entry_point"],
                diagnostics,
                file,
                row.line,
                "entry_point",
                line_counts,
            )
        if "critical_operation" in data:
            validate_node(
                data["critical_operation"],
                diagnostics,
                file,
                row.line,
                "critical_operation",
                line_counts,
            )

        trace = data.get("trace")
        if not isinstance(trace, list):
            add_error(
                diagnostics,
                "TRACE_TYPE",
                file,
                row.line,
                "trace",
                "trace must be a list",
            )
        else:
            for index, node in enumerate(trace):
                validate_node(
                    node,
                    diagnostics,
                    file,
                    row.line,
                    f"trace[{index}]",
                    line_counts,
                )


def validate_report_rows(
    rows: list[LoadedRow],
    file: Path,
    diagnostics: list[Diagnostic],
) -> None:
    for row in rows:
        data = row.data
        if list(data) != sorted(data):
            add_error(
                diagnostics,
                "ROW_FIELD_ORDER",
                file,
                row.line,
                "",
                "top-level fields must be sorted alphabetically",
            )
        missing = sorted(REPORT_REQUIRED_FIELDS - data.keys())
        if missing:
            add_error(
                diagnostics,
                "REPORT_REQUIRED_FIELDS",
                file,
                row.line,
                "",
                f"missing required fields: {', '.join(missing)}",
            )
        validate_common_record_fields(data, diagnostics, file, row.line)

        num_entries = data.get("num_entries")
        if isinstance(num_entries, bool) or not isinstance(num_entries, int) or num_entries < 1:
            add_error(
                diagnostics,
                "NUM_ENTRIES_VALUE",
                file,
                row.line,
                "num_entries",
                "num_entries must be a positive integer",
            )

        entry_ids = data.get("entry_ids")
        if not isinstance(entry_ids, list) or not all(
            isinstance(item, str) for item in entry_ids
        ):
            add_error(
                diagnostics,
                "REPORT_ENTRY_IDS_TYPE",
                file,
                row.line,
                "entry_ids",
                "entry_ids must be a list of strings",
            )
        elif entry_ids != sorted(set(entry_ids)):
            add_error(
                diagnostics,
                "REPORT_ENTRY_IDS_ORDER",
                file,
                row.line,
                "entry_ids",
                "entry_ids must be unique and sorted",
            )


def validate_id_order_and_uniqueness(
    rows: list[LoadedRow],
    file: Path,
    key: str,
    diagnostics: list[Diagnostic],
) -> None:
    values = [row.data.get(key) for row in rows]
    strings = [value for value in values if isinstance(value, str)]
    if strings != sorted(strings):
        add_error(
            diagnostics,
            "ROW_ORDER",
            file,
            None,
            key,
            f"rows must be sorted by {key}",
        )
    duplicates = sorted(value for value, count in Counter(strings).items() if count > 1)
    if duplicates:
        add_error(
            diagnostics,
            "ROW_DUPLICATE_ID",
            file,
            None,
            key,
            f"duplicate IDs: {', '.join(duplicates)}",
        )


def canonical_scalar(entries: list[dict[str, Any]], field: str) -> Any:
    encoded = [json.dumps(entry.get(field), ensure_ascii=False, sort_keys=True) for entry in entries]
    counts = Counter(encoded)
    highest = max(counts.values())
    winners = {value for value, count in counts.items() if count == highest}
    for entry in sorted(entries, key=lambda item: str(item.get("entry_id", ""))):
        value = json.dumps(entry.get(field), ensure_ascii=False, sort_keys=True)
        if value in winners:
            return entry.get(field)
    raise AssertionError("canonical scalar selection requires at least one entry")


def normalize_vuln_ids(values: list[str]) -> list[str]:
    normalized = {value.upper() for value in values}
    return sorted(normalized, key=lambda value: (not value.startswith("CVE-"), value))


def validate_cross_file_links(
    entry_rows: list[LoadedRow],
    report_rows: list[LoadedRow],
    entries_file: Path,
    reports_file: Path,
    diagnostics: list[Diagnostic],
) -> None:
    entries_by_report: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in entry_rows:
        report_id = row.data.get("report_id")
        if isinstance(report_id, str):
            entries_by_report[report_id].append(row.data)

    reports_by_id: dict[str, LoadedRow] = {}
    for row in report_rows:
        report_id = row.data.get("report_id")
        if isinstance(report_id, str) and report_id not in reports_by_id:
            reports_by_id[report_id] = row

    for report_id, entries in sorted(entries_by_report.items()):
        report_row = reports_by_id.get(report_id)
        if report_row is None:
            add_error(
                diagnostics,
                "ENTRY_REPORT_MISSING",
                entries_file,
                None,
                report_id,
                "entries reference a report_id absent from reports.jsonl",
            )
            continue

        report = report_row.data
        expected_entry_ids = sorted(
            str(entry.get("entry_id")) for entry in entries if isinstance(entry.get("entry_id"), str)
        )
        if report.get("entry_ids") != expected_entry_ids:
            add_error(
                diagnostics,
                "REPORT_ENTRY_IDS_MISMATCH",
                reports_file,
                report_row.line,
                "entry_ids",
                f"expected {expected_entry_ids!r} from entries.jsonl",
            )
        if report.get("num_entries") != len(expected_entry_ids):
            add_error(
                diagnostics,
                "REPORT_NUM_ENTRIES_MISMATCH",
                reports_file,
                report_row.line,
                "num_entries",
                f"expected {len(expected_entry_ids)} from entries.jsonl",
            )

        for field in ("source_link", "origin", "project", "repo_url", "commit"):
            expected = canonical_scalar(entries, field)
            if report.get(field) != expected:
                add_error(
                    diagnostics,
                    "REPORT_CANONICAL_MISMATCH",
                    reports_file,
                    report_row.line,
                    field,
                    f"expected canonical value {expected!r} from entries.jsonl",
                )

        entry_vuln_ids = [
            vuln_id
            for entry in entries
            for vuln_id in entry.get("vuln_ids", [])
            if isinstance(vuln_id, str)
        ]
        expected_vuln_ids = normalize_vuln_ids(entry_vuln_ids)
        if report.get("vuln_ids") != expected_vuln_ids:
            add_error(
                diagnostics,
                "REPORT_VULN_IDS_MISMATCH",
                reports_file,
                report_row.line,
                "vuln_ids",
                f"expected normalized union {expected_vuln_ids!r}",
            )

    for report_id, report_row in sorted(reports_by_id.items()):
        if report_id not in entries_by_report:
            add_error(
                diagnostics,
                "REPORT_ENTRIES_MISSING",
                reports_file,
                report_row.line,
                "report_id",
                "report has no corresponding entries",
            )


def validate_dataset(entries_file: Path, reports_file: Path) -> ValidationResult:
    diagnostics: list[Diagnostic] = []
    line_counts: Counter[str] = Counter()
    entry_rows = load_jsonl(entries_file, diagnostics)
    report_rows = load_jsonl(reports_file, diagnostics)

    validate_entry_rows(entry_rows, entries_file, diagnostics, line_counts)
    validate_report_rows(report_rows, reports_file, diagnostics)
    validate_id_order_and_uniqueness(entry_rows, entries_file, "entry_id", diagnostics)
    validate_id_order_and_uniqueness(report_rows, reports_file, "report_id", diagnostics)
    validate_cross_file_links(
        entry_rows,
        report_rows,
        entries_file,
        reports_file,
        diagnostics,
    )

    entry_report_ids = {
        row.data.get("report_id")
        for row in entry_rows
        if isinstance(row.data.get("report_id"), str)
    }
    report_ids = {
        row.data.get("report_id")
        for row in report_rows
        if isinstance(row.data.get("report_id"), str)
    }
    stats = {
        "entries": len(entry_rows),
        "reports": len(report_rows),
        "linked_advisories": len(entry_report_ids & report_ids),
        "verified_entries": sum(row.data.get("verify") == 1 for row in entry_rows),
        "integer_node_locations": line_counts["integer"],
        "range_node_locations": line_counts["range"],
    }
    ordered = tuple(
        sorted(
            diagnostics,
            key=lambda item: (
                item.file,
                item.line if item.line is not None else 0,
                item.path,
                item.code,
                item.message,
            ),
        )
    )
    return ValidationResult(diagnostics=ordered, stats=stats)


def print_result(result: ValidationResult) -> None:
    stats = result.stats
    print("VulnGym dataset validation")
    print("==========================")
    print(f"reports: {stats['reports']}")
    print(f"entries: {stats['entries']}")
    print(f"linked advisories: {stats['linked_advisories']}")
    print(f"verified entries: {stats['verified_entries']}")
    print(
        "node locations: "
        f"{stats['integer_node_locations']} integers, "
        f"{stats['range_node_locations']} ranges"
    )
    print(f"errors: {len(result.diagnostics)}")
    if result.ok:
        print("OK: dataset invariants verified")
        return
    print()
    for diagnostic in result.diagnostics:
        print(diagnostic.render())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate VulnGym JSONL schema and cross-file invariants."
    )
    parser.add_argument(
        "--entries",
        type=Path,
        default=DEFAULT_ENTRIES,
        help="entries JSONL file (default: data/entries.jsonl)",
    )
    parser.add_argument(
        "--reports",
        type=Path,
        default=DEFAULT_REPORTS,
        help="reports JSONL file (default: data/reports.jsonl)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="optional path for a machine-readable validation report",
    )
    args = parser.parse_args(argv)

    result = validate_dataset(args.entries, args.reports)
    print_result(result)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        with args.json_out.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(result.to_dict(), handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        print(f"JSON report: {args.json_out}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
