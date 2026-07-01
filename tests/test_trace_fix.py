import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import trace_fix


def make_entry(
    trace,
    *,
    entry_line=100,
    critical_line=160,
    entry_file="same.py",
    critical_file=None,
):
    return {
        "entry_id": "entry-test",
        "report_id": "GHSA-TEST-0000-0000",
        "source_link": "https://github.com/advisories/GHSA-test-0000-0000",
        "vuln_ids": ["GHSA-TEST-0000-0000"],
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "demo",
        "repo_url": "https://github.com/example/demo",
        "commit": "a" * 40,
        "vuln_title": "demo vuln",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "verify": 0,
        "entry_point": {
            "file": entry_file,
            "line": entry_line,
            "code": "entry",
            "desc": "entry",
        },
        "critical_operation": {
            "file": critical_file or entry_file,
            "line": critical_line,
            "code": "critical",
            "desc": "critical",
        },
        "trace": trace,
    }


def test_entry_00103_style_case_is_flagged():
    entry = make_entry(
        trace=[
            {
                "file": "packages/cli/src/webhooks/webhook-helpers.ts",
                "line": "605-614",
                "code": "runData.httpResponse = res;",
                "desc": "helper",
            }
        ],
        entry_line=615,
        critical_line=700,
        entry_file="packages/cli/src/webhooks/webhook-helpers.ts",
    )

    issues = trace_fix.analyze_entry(entry)

    assert len(issues) == 1
    assert issues[0].issue_type == trace_fix.ISSUE_TYPE_ORDER_BEFORE_ENTRY


def test_fix_mode_removes_same_file_order_issue():
    entry = make_entry(
        trace=[{"file": "same.py", "line": 70, "code": "helper", "desc": "helper"}],
        entry_line=100,
    )

    issues = trace_fix.analyze_entry(entry)
    new_trace, updated_issues = trace_fix.apply_fixes(entry, issues)

    assert new_trace == []
    assert updated_issues[0].action == trace_fix.ACTION_REMOVED


def test_fix_mode_keeps_nearby_same_file_order_issue_for_review():
    entry = make_entry(
        trace=[{"file": "same.py", "line": "90-99", "code": "helper", "desc": "helper"}],
        entry_line=100,
    )

    issues = trace_fix.analyze_entry(entry)
    new_trace, updated_issues = trace_fix.apply_fixes(entry, issues)

    assert new_trace == entry["trace"]
    assert updated_issues[0].action == trace_fix.ACTION_RECORDED
    assert "kept for manual review" in updated_issues[0].reason


def test_fix_mode_removes_duplicate_trace_node_after_first_occurrence():
    entry = make_entry(
        trace=[
            {"file": "same.py", "line": 110, "code": "dup", "desc": "first"},
            {"file": "same.py", "line": 110, "code": "dup", "desc": "second"},
        ],
    )

    issues = trace_fix.analyze_entry(entry)
    new_trace, updated_issues = trace_fix.apply_fixes(entry, issues)

    assert issues[0].issue_type == trace_fix.ISSUE_TYPE_DUPLICATE
    assert new_trace == [entry["trace"][0]]
    assert updated_issues[0].action == trace_fix.ACTION_REMOVED


def test_duplicate_desc_conflict_is_recorded_without_merge():
    entry = make_entry(
        trace=[
            {"file": "same.py", "line": 110, "code": "dup", "desc": "first"},
            {"file": "same.py", "line": 110, "code": "dup", "desc": "second"},
        ],
    )

    issues = trace_fix.analyze_entry(entry)

    assert issues[0].desc_conflict is True
    assert "was not merged" in issues[0].reason


def test_dry_run_writes_compact_issue_log(tmp_path):
    input_path = tmp_path / "entries.jsonl"
    output_path = tmp_path / "entries.fixed.jsonl"
    log_path = tmp_path / "trace_fix_log.json"
    report_path = tmp_path / "trace_fix_report.json"

    input_path.write_text(
        json.dumps(
            make_entry(
                trace=[{"file": "same.py", "line": 20, "code": "far-helper", "desc": "helper"}],
            ),
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    args = trace_fix.build_arg_parser().parse_args(
        [
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--log",
            str(log_path),
            "--report",
            str(report_path),
            "--mode",
            "dry-run",
        ]
    )

    exit_code = trace_fix.run(args)
    payload = json.loads(log_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report_path.exists()
    assert not output_path.exists()
    assert payload["issues"][0]["issue_type"] == trace_fix.ISSUE_TYPE_ORDER_BEFORE_ENTRY


def test_fix_mode_writes_schema_valid_output(tmp_path):
    input_path = tmp_path / "entries.jsonl"
    output_path = tmp_path / "entries.fixed.jsonl"
    log_path = tmp_path / "trace_fix_log.json"
    report_path = tmp_path / "trace_fix_report.json"

    input_path.write_text(
        json.dumps(
            make_entry(
                trace=[
                    {"file": "same.py", "line": 20, "code": "far-helper", "desc": "helper"},
                    {"file": "same.py", "line": 120, "code": "keep", "desc": "keep"},
                ],
            ),
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    args = trace_fix.build_arg_parser().parse_args(
        [
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--log",
            str(log_path),
            "--report",
            str(report_path),
            "--mode",
            "fix",
        ]
    )

    exit_code = trace_fix.run(args)
    output_entries = trace_fix.load_jsonl(output_path)
    payload = json.loads(log_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert log_path.exists()
    assert report_path.exists()
    trace_fix.validate_entries_schema(output_entries)
    assert output_entries[0]["trace"] == [{"file": "same.py", "line": 120, "code": "keep", "desc": "keep"}]
    assert payload["issues"][0]["action"] == trace_fix.ACTION_REMOVED
    assert report["statistics"]["auto_fixed_count"] == 1
    assert report["statistics"]["review_required_count"] == 0


def test_validate_entries_schema_rejects_invalid_line():
    entries = [
        make_entry(
            trace=[{"file": "same.py", "line": 0, "code": "step", "desc": "step"}],
        )
    ]

    try:
        trace_fix.validate_entries_schema(entries)
    except SystemExit as exc:
        assert "line must be a positive integer or start-end string" in str(exc)
    else:
        raise AssertionError("expected schema validation to fail")


def test_validate_entries_schema_rejects_invalid_verify():
    entries = [make_entry(trace=[])]
    entries[0]["verify"] = 2

    try:
        trace_fix.validate_entries_schema(entries)
    except SystemExit as exc:
        assert "verify must be 0 or 1" in str(exc)
    else:
        raise AssertionError("expected schema validation to fail")
