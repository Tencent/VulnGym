"""Data models for fix_entries."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MatchResult:
    """Result of checking one node against the source repo."""
    entry_id: str
    node_path: str                      # "entry_point" | "critical_operation" | "trace[0]"
    original_file: str
    original_line_raw: object           # original int or str from JSON
    original_line_range: tuple          # normalized (start, end)
    original_code: str
    original_desc: Optional[str]

    # Match outcome
    status: str = ""                    # "exact_match" | "fixed_line" | "fixed_file" | "needs_human"
    new_file: Optional[str] = None
    new_line_range: Optional[tuple] = None  # (start, end)
    new_desc: Optional[str] = None
    strategy: str = ""                  # "exact" | "nearby_5" | "file_wide" | "repo_wide" | "context_disambig" | ""
    match_count: int = 0
    needs_human_reason: str = ""        # UNMATCHABLE_CODE | EMPTY_CODE | TRUNCATED_CODE | MULTIPLE_MATCHES | NO_MATCH | FILE_NOT_FOUND
    detail: str = ""                    # human-readable detail for needs_human
    candidates: list = field(default_factory=list)  # [(file, line), ...] for multiple matches

    # Structural warnings (non-fatal)
    is_self_referencing: bool = False
    self_ref_type: str = ""             # "trace_starts_at_entry" | "trace_ends_at_critical" | "both"


@dataclass
class FixRecord:
    """One row in fix_diff.csv."""
    entry_id: str
    node_path: str
    field: str                          # "line" | "file" | "desc"
    old_value: str
    new_value: str
    strategy: str


@dataclass
class HumanRecord:
    """One row in needs_human.csv."""
    entry_id: str
    node_path: str
    reason_code: str
    detail: str
    original_file: str
    original_line: str
    original_code_preview: str


@dataclass
class StructuralRecord:
    """One row in structural_report.csv."""
    entry_id: str
    issue_type: str
    detail: str
