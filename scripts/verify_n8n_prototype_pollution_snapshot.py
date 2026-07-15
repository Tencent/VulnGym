#!/usr/bin/env python3
"""Verify the n8n prototype-pollution snapshot and semantic anchors."""

from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "GHSA-MXRG-77HM-89HV"
TARGET_IDS = ("entry-00359", "entry-00360", "entry-00361")

OLD_COMMIT = "732f2a3d3ddba59fb6e51bf2534fd33792a2cde3"
VULNERABLE_COMMIT = "f7c36840fb112039ae54423c40f1976dc6cb1f19"
XML_FIX_COMMIT = "ba687dad5eb7377b43882bcb404709935cadbe6c"
GSUITE_FIX_COMMIT = "2d9a2ec76e180b54e8091e31b1e0638c909abd99"

GSUITE = "packages/nodes-base/nodes/Google/GSuiteAdmin/GSuiteAdmin.node.ts"
XML = "packages/nodes-base/nodes/Xml/Xml.node.ts"


class VerificationError(RuntimeError):
    """Raised when the repaired dataset or upstream evidence is inconsistent."""


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def validate_dataset(
    entries: list[dict[str, Any]], reports: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    targets = {row["entry_id"]: row for row in entries if row.get("entry_id") in TARGET_IDS}
    if set(targets) != set(TARGET_IDS):
        raise VerificationError(f"target entry set mismatch: {sorted(targets)}")

    report = next((row for row in reports if row.get("report_id") == REPORT_ID), None)
    if report is None:
        raise VerificationError(f"missing report: {REPORT_ID}")
    if report.get("commit") != VULNERABLE_COMMIT:
        raise VerificationError("report is not pinned to the common vulnerable snapshot")

    for entry_id, entry in targets.items():
        if entry.get("report_id") != REPORT_ID:
            raise VerificationError(f"{entry_id}: unexpected report_id")
        if entry.get("commit") != VULNERABLE_COMMIT:
            raise VerificationError(f"{entry_id}: mixed or stale snapshot")
        if entry.get("verify") != 0:
            raise VerificationError(f"{entry_id}: changed semantics must await maintainer review")

    semantic_expectations = {
        "entry-00359": ("additionalFields.customFields", "[fieldName] = value"),
        "entry-00360": ("updateFields.customFields", "[fieldName] = value"),
        "entry-00361": ("getNodeParameter('options'", "parseStringPromise"),
    }
    for entry_id, (source, sink) in semantic_expectations.items():
        if source not in targets[entry_id]["entry_point"]["code"]:
            raise VerificationError(f"{entry_id}: incorrect external-input anchor")
        if sink not in targets[entry_id]["critical_operation"]["code"]:
            raise VerificationError(f"{entry_id}: incorrect critical-operation anchor")
    return targets


def line_span(value: int | str) -> tuple[int, int]:
    if isinstance(value, int):
        return value, value
    start, end = value.split("-", 1)
    return int(start), int(end)


def source_slice(source: str, line: int | str) -> str:
    start, end = line_span(line)
    return "\n".join(source.splitlines()[start - 1 : end])


def request(url: str) -> bytes:
    headers = {"User-Agent": "VulnGym-issue-6-verifier"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return response.read()


def raw_file(commit: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/n8n-io/n8n/{commit}/{path}"
    return request(url).decode("utf-8")


def commit_parent(commit: str) -> str:
    url = f"https://api.github.com/repos/n8n-io/n8n/commits/{commit}"
    payload = json.loads(request(url))
    return payload["parents"][0]["sha"]


def compare_commits(base: str, head: str) -> dict[str, Any]:
    url = f"https://api.github.com/repos/n8n-io/n8n/compare/{base}...{head}"
    return json.loads(request(url))


def verify_upstream(targets: dict[str, dict[str, Any]]) -> None:
    sources = {
        GSUITE: raw_file(VULNERABLE_COMMIT, GSUITE),
        XML: raw_file(VULNERABLE_COMMIT, XML),
    }
    checked = 0
    for entry_id, entry in targets.items():
        for node in (entry["entry_point"], entry["critical_operation"], *entry["trace"]):
            actual = source_slice(sources[node["file"]], node["line"])
            if actual != node["code"]:
                raise VerificationError(
                    f"source mismatch: {entry_id} {node['file']}:{node['line']}"
                )
            checked += 1

    old_xml = raw_file(OLD_COMMIT, XML)
    fixed_gsuite = raw_file(GSUITE_FIX_COMMIT, GSUITE)
    guard = "const forbiddenKeys = ['__proto__', 'constructor', 'prototype'];"
    if guard in sources[XML]:
        raise VerificationError("selected snapshot already contains the XML fix")
    if guard not in old_xml:
        raise VerificationError("old snapshot does not contain the expected XML fix")
    if "setSafeObjectProperty(customSchemas, schemaName, {})" not in fixed_gsuite:
        raise VerificationError("GSuite fix evidence is missing")
    if commit_parent(XML_FIX_COMMIT) != VULNERABLE_COMMIT:
        raise VerificationError("XML fix parent changed")
    if commit_parent(GSUITE_FIX_COMMIT) != OLD_COMMIT:
        raise VerificationError("GSuite fix parent changed")

    comparison = compare_commits(VULNERABLE_COMMIT, OLD_COMMIT)
    if comparison.get("status") != "ahead" or comparison.get("behind_by") != 0:
        raise VerificationError("selected snapshot is not an ancestor of the old snapshot")

    print(f"upstream source nodes: {checked}/{checked} exact matches")
    print(f"XML fix parent: {XML_FIX_COMMIT[:7]} -> {VULNERABLE_COMMIT[:7]}")
    print(f"GSuite fix parent: {GSUITE_FIX_COMMIT[:7]} -> {OLD_COMMIT[:7]}")
    print("old snapshot already contains XML forbidden-key validation: yes")
    print(
        "selected snapshot predates both fixes: yes "
        f"({comparison['ahead_by']} commits before old snapshot)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=Path, default=ROOT / "data" / "entries.jsonl")
    parser.add_argument("--reports", type=Path, default=ROOT / "data" / "reports.jsonl")
    parser.add_argument("--check-upstream", action="store_true")
    args = parser.parse_args(argv)

    targets = validate_dataset(read_jsonl(args.entries), read_jsonl(args.reports))
    print(f"dataset target entries: {len(targets)}/{len(TARGET_IDS)} valid")
    if args.check_upstream:
        verify_upstream(targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
