from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.trace_cleanup.cli import main
from tools.trace_cleanup.io import load_jsonl, write_jsonl_atomic

from .fixtures import entry, node


def write_input(path: Path, rows: list[dict]) -> bytes:
    data = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows).encode()
    path.write_bytes(data)
    return data


class CliTests(unittest.TestCase):
    def test_check_does_not_create_fixed_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            reports = root / "reports"
            fixed = root / "entries.trace_fixed.jsonl"
            write_input(source, [entry()])
            self.assertEqual(
                main(["check", "--input", str(source), "--reports-dir", str(reports)]),
                0,
            )
            self.assertFalse(fixed.exists())
            self.assertTrue((reports / "trace_findings.csv").exists())
            self.assertFalse((reports / "trace_fix_log.csv").exists())

    def test_fix_removes_safe_duplicate_but_not_order_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            output = root / "fixed.jsonl"
            reports = root / "reports"
            repeated = node(5, code="repeat", desc="same")
            write_input(source, [entry(trace=[repeated, repeated, node(20)])])
            main(
                [
                    "fix",
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--reports-dir",
                    str(reports),
                ]
            )
            fixed = load_jsonl(output)
            self.assertEqual([n["line"] for n in fixed[0]["trace"]], [5, 20])
            self.assertTrue((reports / "trace_fix_log.csv").exists())

    def test_explicit_remove_definite_and_verified_protection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            output = root / "fixed.jsonl"
            write_input(
                source,
                [
                    entry(entry_id="entry-00001", trace=[node(5)]),
                    entry(entry_id="entry-00002", verify=1, trace=[node(5)]),
                ],
            )
            main(
                [
                    "fix",
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--reports-dir",
                    str(root / "reports"),
                    "--order-action",
                    "remove-definite",
                ]
            )
            rows = load_jsonl(output)
            self.assertEqual(rows[0]["trace"], [])
            self.assertEqual(len(rows[1]["trace"]), 1)

    def test_fix_refuses_to_overwrite_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "entries.jsonl"
            original = write_input(source, [entry()])
            with self.assertRaises(SystemExit):
                main(["fix", "--input", str(source), "--output", str(source)])
            self.assertEqual(source.read_bytes(), original)

    def test_entry_filter_preserves_unselected_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            output = root / "fixed.jsonl"
            repeated = node(12, code="repeat", desc="same")
            rows = [
                entry(entry_id="entry-00001", trace=[repeated, repeated]),
                entry(entry_id="entry-00002", trace=[repeated, repeated]),
            ]
            write_input(source, rows)
            main(
                [
                    "fix",
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--reports-dir",
                    str(root / "reports"),
                    "--entry-id",
                    "entry-00001",
                ]
            )
            fixed = load_jsonl(output)
            self.assertEqual(len(fixed[0]["trace"]), 1)
            self.assertEqual(fixed[1], rows[1])

    def test_output_is_deterministic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            first = root / "first.jsonl"
            second = root / "second.jsonl"
            third = root / "third.jsonl"
            repeated = node(12, code="repeat", desc="same")
            write_input(source, [entry(trace=[repeated, repeated])])
            for output, reports in [
                (first, root / "reports1"),
                (second, root / "reports2"),
            ]:
                main(
                    [
                        "fix",
                        "--input",
                        str(source),
                        "--output",
                        str(output),
                        "--reports-dir",
                        str(reports),
                    ]
                )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                (root / "reports1" / "trace_summary.json").read_bytes(),
                (root / "reports2" / "trace_summary.json").read_bytes(),
            )
            main(
                [
                    "fix",
                    "--input",
                    str(first),
                    "--output",
                    str(third),
                    "--reports-dir",
                    str(root / "reports3"),
                ]
            )
            self.assertEqual(first.read_bytes(), third.read_bytes())
            summary = json.loads((root / "reports3" / "trace_summary.json").read_text())
            self.assertEqual(summary["changed_entries"], 0)

    def test_atomic_write_failure_leaves_no_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output.jsonl"
            with mock.patch("tools.trace_cleanup.io.os.replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    write_jsonl_atomic(output, [entry()])
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob("*.tmp")), [])

    def test_input_hash_is_unchanged_after_fix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            output = root / "fixed.jsonl"
            original = write_input(source, [entry()])
            original_hash = hashlib.sha256(original).hexdigest()
            main(
                [
                    "fix",
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--reports-dir",
                    str(root / "reports"),
                ]
            )
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original_hash)

    def test_zero_change_fix_is_byte_identical_including_crlf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entries.jsonl"
            output = root / "fixed.jsonl"
            row = json.dumps(entry(), ensure_ascii=False).encode("utf-8")
            source.write_bytes(row + b"\r\n")
            main(
                [
                    "fix",
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--reports-dir",
                    str(root / "reports"),
                ]
            )
            self.assertEqual(output.read_bytes(), source.read_bytes())
