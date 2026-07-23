from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    entry_id: str
    report_id: str
    verify: int
    rule_id: str
    field_path: str
    trace_index: int
    file: str
    raw_line: int | str
    relation: str
    reason: str
    boundary_role: str = ""
    boundary_file: str = ""
    boundary_raw_line: int | str | None = None
    before: Any = None
    after: Any = None
    kept_index: int | None = None
    indices: tuple[int, ...] = ()
    safe_duplicate: bool = False


@dataclass(frozen=True)
class DetectionResult:
    findings: tuple[Finding, ...]
    entries_scanned: int
    trace_nodes_scanned: int
    duplicate_groups: int
    duplicate_extra_nodes: int


@dataclass(frozen=True)
class Decision:
    finding: Finding
    status: str
    remove_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class ApplyResult:
    entries: list[dict]
    changed_entries: int
    removed_nodes: int
