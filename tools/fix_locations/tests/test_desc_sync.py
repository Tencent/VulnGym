# -*- coding: utf-8 -*-
"""Unit tests for mechanical desc sync."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "scripts"))
from desc_sync_lib import try_sync  # noqa: E402


class TestDescSync(unittest.TestCase):
    def test_cn_line_to_range(self):
        d = "message-handler.ts 第 549 行 if 条件块是触发门。"
        nd, st = try_sync(d, 549, "549-557")
        self.assertEqual(st, "would_update")
        self.assertIn("第 549-557 行", nd)
        self.assertNotIn("第 549 行", nd)

    def test_cn_line_no_space(self):
        d = "第549行 if 条件块"
        nd, st = try_sync(d, 549, "549-557")
        self.assertEqual(st, "would_update")
        self.assertEqual(nd, "第 549-557 行 if 条件块")

    def test_en_line(self):
        d = "At line 42 the check runs."
        nd, st = try_sync(d, 42, 45)
        self.assertEqual(st, "would_update")
        self.assertEqual(nd, "At line 45 the check runs.")

    def test_no_anchor(self):
        d = "入口函数接收 HTTP 请求后解析。"
        nd, st = try_sync(d, 1444, "1444-1449")
        self.assertEqual(st, "no_anchor")
        self.assertIsNone(nd)

    def test_no_desc(self):
        nd, st = try_sync("", 1, 2)
        self.assertEqual(st, "no_desc")

    def test_wrong_line_mention_untouched(self):
        d = "第 100 行是别的东西，真正漏洞在别处。"
        nd, st = try_sync(d, 549, "549-557")
        self.assertEqual(st, "no_anchor")

    def test_idempotent_after_sync(self):
        d = "第 549 行触发"
        nd, st = try_sync(d, 549, "549-557")
        self.assertEqual(st, "would_update")
        nd2, st2 = try_sync(nd, 549, "549-557")
        # new desc already has range starting 549 — may still match as mention of 549
        # second pass: old_line still 549, desc has "第 549-557 行" → CN_RANGE matches → would rewrite same
        self.assertIn(st2, ("would_update", "anchor_but_unchanged"))
        if st2 == "would_update":
            self.assertEqual(nd2, nd)


if __name__ == "__main__":
    unittest.main()
