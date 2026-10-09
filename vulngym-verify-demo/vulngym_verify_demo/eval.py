# -*- coding: utf-8 -*-
"""Frozen offline evaluator for VulnGym's eight verification fields.

Core metric contract:

* ``field_accuracy`` compares all eight gold statuses exactly. Missing reports,
  missing fields and invalid statuses are prediction errors.
* ``error_recall`` is entry-level: an entry with at least one gold
  ``incorrect`` field is found only when its predicted ``verdict`` is
  ``incorrect``. ``uncertain`` does not count as found.
* Invalid-input fixtures and reports not represented in gold are excluded from
  these core metrics and reported separately.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


ALL_FIELDS: Tuple[str, ...] = (
    "entry_point",
    "critical_operation",
    "commit",
    "vuln_ids",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "trace",
)
STATUS_VALUES = frozenset({"correct", "incorrect", "uncertain"})
VERDICT_VALUES = STATUS_VALUES
INVALID_INPUT_PREFIX = "__invalid_input__"


def _is_invalid_fixture(entry_id: str) -> bool:
    return entry_id.startswith(INVALID_INPUT_PREFIX)


def _normalise_gold_row(row: Any, *, where: str) -> Dict[str, Any]:
    """Validate one gold row and convert both supported formats to 8 statuses."""
    if not isinstance(row, dict):
        raise ValueError(f"{where}: gold row must be an object")
    entry_id = row.get("entry_id")
    verdict = row.get("verdict")
    if not isinstance(entry_id, str) or not entry_id:
        raise ValueError(f"{where}: entry_id must be a non-empty string")
    if verdict not in VERDICT_VALUES:
        raise ValueError(f"{where}: verdict must be one of {sorted(VERDICT_VALUES)}")

    raw_incorrect = row.get("incorrect_fields", [])
    if not isinstance(raw_incorrect, list) or not all(isinstance(name, str) for name in raw_incorrect):
        raise ValueError(f"{where}: incorrect_fields must be a list of field names")
    if len(set(raw_incorrect)) != len(raw_incorrect) or any(name not in ALL_FIELDS for name in raw_incorrect):
        raise ValueError(f"{where}: incorrect_fields must be unique names from the eight core fields")

    raw_fields = row.get("fields")
    if raw_fields is not None:
        if not isinstance(raw_fields, dict):
            raise ValueError(f"{where}: fields must be an object")
        missing = [name for name in ALL_FIELDS if name not in raw_fields]
        invalid = [name for name in ALL_FIELDS if raw_fields.get(name) not in STATUS_VALUES]
        if missing or invalid:
            raise ValueError(f"{where}: explicit fields must provide valid statuses for all eight fields")
        fields = {name: raw_fields[name] for name in ALL_FIELDS}
        derived_incorrect = [name for name in ALL_FIELDS if fields[name] == "incorrect"]
        if raw_incorrect and set(raw_incorrect) != set(derived_incorrect):
            raise ValueError(f"{where}: incorrect_fields conflicts with explicit fields")
        gold_format = "explicit"
    else:
        # Compatibility format has only a verdict plus incorrect field names.
        # For an incorrect/uncertain entry, unspecified fields are intentionally
        # ``uncertain`` rather than fabricated ``correct`` labels.
        default = "correct" if verdict == "correct" else "uncertain"
        fields = {name: ("incorrect" if name in raw_incorrect else default) for name in ALL_FIELDS}
        derived_incorrect = list(raw_incorrect)
        gold_format = "compat"

    if verdict == "correct" and derived_incorrect:
        raise ValueError(f"{where}: a correct verdict cannot have incorrect fields")
    if verdict == "uncertain" and derived_incorrect:
        raise ValueError(f"{where}: an uncertain verdict cannot have incorrect fields")
    if verdict == "incorrect" and not derived_incorrect:
        raise ValueError(f"{where}: an incorrect verdict needs at least one incorrect field")

    return {
        "entry_id": entry_id,
        "verdict": verdict,
        "fields": fields,
        "incorrect_fields": derived_incorrect,
        "format": gold_format,
    }


def load_gold(path: Path | str) -> Dict[str, Dict[str, Any]]:
    """Load and validate explicit or compatible gold JSONL.

    The returned mapping always contains a complete eight-field status map,
    making the metric denominator stable and auditable.
    """
    gold: Dict[str, Dict[str, Any]] = {}
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"gold line {line_no}: invalid JSON") from exc
            item = _normalise_gold_row(row, where=f"gold line {line_no}")
            if item["entry_id"] in gold:
                raise ValueError(f"gold line {line_no}: duplicate entry_id {item['entry_id']!r}")
            gold[item["entry_id"]] = item
    return gold


def _normalise_gold_mapping(gold: Mapping[str, Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Accept legacy in-memory mappings while applying the same validation."""
    normalised: Dict[str, Dict[str, Any]] = {}
    for map_key, item in gold.items():
        row = dict(item)
        row.setdefault("entry_id", map_key)
        normalised[map_key] = _normalise_gold_row(row, where=f"gold entry {map_key!r}")
    return normalised


def _report_index(reports: Iterable[Mapping[str, Any]]) -> Tuple[Dict[str, Mapping[str, Any]], int]:
    indexed: Dict[str, Mapping[str, Any]] = {}
    duplicates = set()
    for report in reports:
        entry_id = report.get("entry_id") if isinstance(report, Mapping) else None
        if not isinstance(entry_id, str):
            continue
        if entry_id in indexed:
            duplicates.add(entry_id)
        indexed[entry_id] = report
    # A duplicate is not a trustworthy prediction. Remove it so it scores as a
    # missing report if the entry exists in gold.
    for entry_id in duplicates:
        indexed.pop(entry_id, None)
    return indexed, len(duplicates)


def evaluate(reports: List[Dict[str, Any]], gold: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate reports under the frozen field-accuracy and recall definitions."""
    normalised_gold = _normalise_gold_mapping(gold)
    reports_map, duplicate_report_count = _report_index(reports)
    field_hit = field_total = error_hit = error_total = verdict_hit = verdict_total = 0
    field_breakdown: Dict[str, Dict[str, int]] = {name: {"hit": 0, "total": 0} for name in ALL_FIELDS}
    per_entry: List[Dict[str, Any]] = []
    excluded_invalid_entries = 0

    for entry_id, item in normalised_gold.items():
        report = reports_map.get(entry_id)
        if _is_invalid_fixture(entry_id):
            excluded_invalid_entries += 1
            per_entry.append({
                "entry_id": entry_id,
                "included": False,
                "reason": "invalid_input_fixture",
                "verdict_pred": report.get("verdict") if report else None,
                "verdict_gold": item["verdict"],
                "incorrect_pred": [],
                "incorrect_gold": item["incorrect_fields"],
            })
            continue

        verdict_total += 1
        verdict_pred = report.get("verdict") if report else None
        if verdict_pred == item["verdict"]:
            verdict_hit += 1

        fields_pred = report.get("fields") if isinstance(report, Mapping) else None
        if not isinstance(fields_pred, Mapping):
            fields_pred = {}
        for name in ALL_FIELDS:
            field_total += 1
            field_breakdown[name]["total"] += 1
            actual = fields_pred.get(name)
            actual_status = actual.get("status") if isinstance(actual, Mapping) else None
            if actual_status == item["fields"][name]:
                field_hit += 1
                field_breakdown[name]["hit"] += 1

        needs_incorrect = bool(item["incorrect_fields"])
        if needs_incorrect:
            error_total += 1
            if verdict_pred == "incorrect":
                error_hit += 1

        per_entry.append({
            "entry_id": entry_id,
            "included": True,
            "verdict_pred": verdict_pred,
            "verdict_gold": item["verdict"],
            "incorrect_pred": [
                name for name, value in fields_pred.items()
                if isinstance(value, Mapping) and value.get("status") == "incorrect"
            ],
            "incorrect_gold": item["incorrect_fields"],
        })

    unexpected_report_count = sum(
        1 for entry_id in reports_map
        if entry_id not in normalised_gold or _is_invalid_fixture(entry_id)
    )
    metrics = {
        "n_entries": verdict_total,
        "field_accuracy": field_hit / field_total if field_total else 0.0,
        "error_recall": error_hit / error_total if error_total else 1.0,
        "verdict_accuracy": verdict_hit / verdict_total if verdict_total else 0.0,
        "field_total": field_total,
        "field_hit": field_hit,
        "error_total": error_total,
        "error_hit": error_hit,
        "verdict_total": verdict_total,
        "verdict_correct": verdict_hit,
        "excluded_invalid_entries": excluded_invalid_entries,
        "unexpected_report_count": unexpected_report_count,
        "duplicate_report_count": duplicate_report_count,
        "per_entry": per_entry,
    }
    metrics["field_breakdown"] = {
        name: {
            "accuracy": values["hit"] / values["total"] if values["total"] else None,
            "hit": values["hit"],
            "total": values["total"],
        }
        for name, values in field_breakdown.items()
    }
    return metrics


def format_metrics(metrics: Dict[str, Any]) -> str:
    """Render the frozen metrics in a stable human-readable format."""
    # ``verdict_total`` was added with the frozen metrics contract.  Retain
    # compatibility with callers that only supplied the older ``n_entries``.
    verdict_total = metrics.get("verdict_total", metrics["n_entries"])
    lines = [
        "=" * 72,
        f"VulnGym 字段级验证 — 评测 (n_entries={metrics['n_entries']})",
        f"  field-level accuracy : {metrics['field_accuracy']:.3f}  ({metrics['field_hit']}/{metrics['field_total']})  [target >= 0.85]",
        f"  error recall         : {metrics['error_recall']:.3f}  ({metrics['error_hit']}/{metrics['error_total']})  [target >= 0.90]",
        f"  verdict accuracy     : {metrics['verdict_accuracy']:.3f}  ({metrics['verdict_correct']}/{verdict_total})",
        f"  excluded invalid     : {metrics.get('excluded_invalid_entries', 0)}",
        f"  unexpected reports   : {metrics.get('unexpected_report_count', 0)}",
        "-" * 72,
        f"  {'field':<20s} {'accuracy':>10s} {'hit':>6s}/{'total':<6s}",
    ]
    for name in ALL_FIELDS:
        breakdown = metrics["field_breakdown"][name]
        accuracy = breakdown["accuracy"]
        accuracy_text = f"{accuracy:.3f}" if accuracy is not None else "n/a"
        lines.append(f"  {name:<20s} {accuracy_text:>10s} {breakdown['hit']:>6d}/{breakdown['total']:<6d}")
    lines.append("-" * 72)
    lines.append("  field accuracy requires exact gold-status matches for all eight fields.")
    lines.append("  error recall counts only gold-error entries predicted with verdict=incorrect.")
    lines.append("=" * 72)
    return "\n".join(lines)
