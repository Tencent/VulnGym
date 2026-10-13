from __future__ import annotations

import unittest

from tools.trace_cleanup.lines import LineSpan, SpanRelation, classify_span, parse_line


class ParseLineTests(unittest.TestCase):
    def test_positive_integer(self) -> None:
        self.assertEqual(parse_line(97), LineSpan(97, 97, 97))

    def test_range(self) -> None:
        self.assertEqual(parse_line("348-352"), LineSpan(348, 352, "348-352"))

    def test_single_line_range(self) -> None:
        self.assertEqual(parse_line("97-97"), LineSpan(97, 97, "97-97"))

    def test_invalid_values(self) -> None:
        invalid = [
            0,
            -1,
            True,
            False,
            1.5,
            "",
            " 1-2",
            "1-2 ",
            "10-5",
            "1-2-3",
            "97",
            [],
            {},
            None,
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_line(value)


class SpanRelationTests(unittest.TestCase):
    def test_all_interval_relations(self) -> None:
        boundary = LineSpan(10, 20, "10-20")
        cases = [
            (LineSpan(1, 9, "1-9"), SpanRelation.BEFORE),
            (LineSpan(21, 30, "21-30"), SpanRelation.AFTER),
            (LineSpan(10, 20, "10-20"), SpanRelation.EQUAL),
            (LineSpan(5, 25, "5-25"), SpanRelation.CONTAINS),
            (LineSpan(12, 18, "12-18"), SpanRelation.CONTAINED),
            (LineSpan(5, 15, "5-15"), SpanRelation.OVERLAP_LEFT),
            (LineSpan(15, 25, "15-25"), SpanRelation.OVERLAP_RIGHT),
        ]
        for span, expected in cases:
            with self.subTest(span=span):
                self.assertEqual(classify_span(span, boundary), expected)
