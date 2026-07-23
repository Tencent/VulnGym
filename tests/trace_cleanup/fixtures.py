from __future__ import annotations

from copy import deepcopy


def node(
    line: object,
    *,
    file: str = "src/example.py",
    code: str | None = None,
    desc: str | None = "step",
    include_desc: bool = True,
) -> dict:
    value = {
        "file": file,
        "line": line,
        "code": code if code is not None else f"code at {line}",
    }
    if include_desc:
        value["desc"] = desc
    return value


def entry(
    *,
    entry_id: str = "entry-00001",
    verify: int = 0,
    entry_point: dict | None = None,
    critical_operation: dict | None = None,
    trace: list[dict] | None = None,
) -> dict:
    return {
        "commit": "a" * 40,
        "critical_operation": deepcopy(
            critical_operation or node(20, code="critical")
        ),
        "entry_id": entry_id,
        "entry_point": deepcopy(entry_point or node(10, code="entry")),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "fixture",
        "repo_url": "https://github.com/example/fixture",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "source_link": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "trace": deepcopy(trace or [node(10, code="entry"), node(20, code="critical")]),
        "verify": verify,
        "vuln_category_l1": "test",
        "vuln_category_l2": "test",
        "vuln_ids": ["GHSA-AAAA-BBBB-CCCC"],
        "vuln_title": "fixture",
    }
