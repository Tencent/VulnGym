# -*- coding: utf-8 -*-
"""Tests for Diff Pack classify + desc dry-run helpers."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import _diffpack_lib as lib  # noqa: E402

spec = importlib.util.spec_from_file_location("desc_sync_dryrun", SCRIPTS / "desc_sync_dryrun.py")
desc_mod = importlib.util.module_from_spec(spec)
assert spec.loader
sys.modules[spec.name] = desc_mod
spec.loader.exec_module(desc_mod)


class TestClassify(unittest.TestCase):
    def test_range_expand(self):
        r = {"old_file": "a.ts", "new_file": "a.ts", "old_line": "10", "new_line": "10-12"}
        self.assertEqual(lib.classify_our_fix(r), "range_expand_same_start")

    def test_line_moved(self):
        r = {"old_file": "a.ts", "new_file": "a.ts", "old_line": "10", "new_line": "14"}
        self.assertEqual(lib.classify_our_fix(r), "line_moved")


class TestDescSync(unittest.TestCase):
    def test_cn_line(self):
        new, st = desc_mod.try_sync("漏洞在第 10 行触发", 10, "12")
        self.assertEqual(st, "would_update")
        self.assertIn("12", new or "")

    def test_no_anchor(self):
        new, st = desc_mod.try_sync("这里没有行号锚点", 10, "12")
        self.assertEqual(st, "no_anchor")
        self.assertIsNone(new)


if __name__ == "__main__":
    unittest.main()
