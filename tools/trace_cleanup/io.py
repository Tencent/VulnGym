from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Iterable

from .lines import parse_line


_ENTRY_ID_RE = re.compile(r"^entry-\d{5}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_GHSA_RE = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
_REQUIRED_TOP_LEVEL = {
    "entry_id",
    "report_id",
    "source_link",
    "vuln_ids",
    "origin",
    "project",
    "repo_url",
    "commit",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "entry_point",
    "critical_operation",
    "trace",
    "verify",
}
_INTERNAL_FIELDS = {
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


def _validate_node(node: object, location: str) -> None:
    if not isinstance(node, dict):
        raise ValueError(f"{location}: node must be an object")
    keys = set(node)
    missing = {"file", "line", "code"} - keys
    extras = keys - {"file", "line", "code", "desc"}
    if missing:
        raise ValueError(f"{location}: missing node keys {sorted(missing)}")
    if extras:
        raise ValueError(f"{location}: unsupported node keys {sorted(extras)}")
    if not isinstance(node["file"], str):
        raise ValueError(f"{location}.file: expected string")
    if not isinstance(node["code"], str):
        raise ValueError(f"{location}.code: expected string")
    if "desc" in node and not isinstance(node["desc"], str):
        raise ValueError(f"{location}.desc: expected string")
    try:
        parse_line(node["line"])
    except ValueError as error:
        raise ValueError(f"{location}.line: {error}") from None


def validate_entries(entries: Iterable[dict]) -> None:
    seen_ids: set[str] = set()
    for row_number, entry in enumerate(entries, 1):
        location = f"entry row {row_number}"
        if not isinstance(entry, dict):
            raise ValueError(f"{location}: expected object")
        missing = _REQUIRED_TOP_LEVEL - set(entry)
        if missing:
            raise ValueError(f"{location}: missing fields {sorted(missing)}")
        forbidden = _INTERNAL_FIELDS & set(entry)
        if forbidden:
            raise ValueError(f"{location}: forbidden fields {sorted(forbidden)}")
        entry_id = entry["entry_id"]
        if not isinstance(entry_id, str) or not _ENTRY_ID_RE.fullmatch(entry_id):
            raise ValueError(f"{location}.entry_id: invalid format")
        if entry_id in seen_ids:
            raise ValueError(f"{location}.entry_id: duplicate {entry_id}")
        seen_ids.add(entry_id)
        if type(entry["verify"]) is not int or entry["verify"] not in (0, 1):
            raise ValueError(f"{location}.verify: expected integer 0 or 1")
        if entry["origin"] != "GitHub Advisory Database (reviewed)":
            raise ValueError(f"{location}.origin: unexpected value")
        if (
            not isinstance(entry["commit"], str)
            or not _COMMIT_RE.fullmatch(entry["commit"])
        ):
            raise ValueError(f"{location}.commit: invalid SHA")
        if (
            not isinstance(entry["repo_url"], str)
            or not entry["repo_url"].startswith("https://github.com/")
        ):
            raise ValueError(f"{location}.repo_url: invalid URL")
        report_id = entry["report_id"]
        if not isinstance(report_id, str) or not _GHSA_RE.fullmatch(report_id):
            raise ValueError(f"{location}.report_id: invalid GHSA id")
        if (
            not isinstance(entry["source_link"], str)
            or "github.com/advisories/" not in entry["source_link"]
            or entry["source_link"].rsplit("/", 1)[-1].upper() != report_id
        ):
            raise ValueError(f"{location}.source_link: does not match report_id")
        if not isinstance(entry["vuln_ids"], list) or not all(
            isinstance(value, str) for value in entry["vuln_ids"]
        ):
            raise ValueError(f"{location}.vuln_ids: expected string list")
        _validate_node(entry["entry_point"], f"{location}.entry_point")
        _validate_node(
            entry["critical_operation"],
            f"{location}.critical_operation",
        )
        if not isinstance(entry["trace"], list):
            raise ValueError(f"{location}.trace: expected list")
        for index, item in enumerate(entry["trace"]):
            _validate_node(item, f"{location}.trace[{index}]")


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                raise ValueError(f"{path}:{line_number}: empty JSONL row")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from None
            rows.append(value)
    validate_entries(rows)
    return rows


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_jsonl_newline(path: Path) -> str:
    """Return the input's first newline style so unchanged output is byte-stable."""
    previous_byte: int | None = None
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            index = chunk.find(b"\n")
            if index >= 0:
                preceded_by_cr = (
                    chunk[index - 1] == 13
                    if index > 0
                    else previous_byte == 13
                )
                return "\r\n" if preceded_by_cr else "\n"
            previous_byte = chunk[-1]
    return "\n"


def _jsonl_bytes(entries: list[dict], newline: str) -> bytes:
    text = "".join(
        json.dumps(entry, ensure_ascii=False) + newline
        for entry in entries
    )
    return text.encode("utf-8")


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def write_jsonl_atomic(
    path: Path,
    entries: list[dict],
    *,
    newline: str = "\n",
) -> None:
    if newline not in {"\n", "\r\n"}:
        raise ValueError("newline must be LF or CRLF")
    validate_entries(entries)
    data = _jsonl_bytes(entries, newline)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        reloaded = load_jsonl(temporary)
        if len(reloaded) != len(entries):
            raise ValueError("temporary JSONL row count changed during validation")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
