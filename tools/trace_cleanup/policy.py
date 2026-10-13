from __future__ import annotations

from collections import defaultdict
from copy import deepcopy

from .models import ApplyResult, Decision, Finding


_DEFINITE_RULES = {"before_entry_definite", "after_critical_definite"}
_OVERLAP_RULES = {"overlap_entry", "overlap_critical"}


def _decide_one(
    finding: Finding,
    *,
    mode: str,
    duplicate_action: str,
    order_action: str,
) -> Decision:
    if finding.rule_id == "cross_file_skipped":
        return Decision(finding, "skipped_cross_file")
    if finding.verify == 1:
        return Decision(finding, "protected_verified")
    if finding.rule_id == "duplicate_trace_node":
        if not finding.safe_duplicate:
            return Decision(finding, "manual_review")
        if mode == "fix" and duplicate_action == "remove-safe":
            return Decision(finding, "auto_fixed", finding.indices[1:])
        return Decision(finding, "reported")
    if finding.rule_id in _DEFINITE_RULES:
        if mode == "fix" and order_action == "remove-definite":
            return Decision(finding, "auto_fixed", (finding.trace_index,))
        return Decision(finding, "reported")
    if finding.rule_id in _OVERLAP_RULES:
        return Decision(finding, "manual_review")
    return Decision(finding, "reported")


def decide_findings(
    findings: list[Finding] | tuple[Finding, ...],
    *,
    mode: str,
    duplicate_action: str,
    order_action: str,
) -> list[Decision]:
    """Apply policy to findings without changing any entry."""
    return [
        _decide_one(
            finding,
            mode=mode,
            duplicate_action=duplicate_action,
            order_action=order_action,
        )
        for finding in findings
    ]


def apply_decisions(entries: list[dict], decisions: list[Decision]) -> ApplyResult:
    """Rebuild traces using approved removals; never mutate the input entries."""
    removals: dict[str, set[int]] = defaultdict(set)
    for decision in decisions:
        if decision.status == "auto_fixed":
            removals[decision.finding.entry_id].update(decision.remove_indices)

    output = deepcopy(entries)
    changed_entries = 0
    removed_nodes = 0
    for entry in output:
        indexes = removals.get(entry["entry_id"], set())
        if not indexes:
            continue
        original_trace = entry["trace"]
        entry["trace"] = [
            item for index, item in enumerate(original_trace)
            if index not in indexes
        ]
        removed = len(original_trace) - len(entry["trace"])
        if removed:
            changed_entries += 1
            removed_nodes += removed
    return ApplyResult(output, changed_entries, removed_nodes)
