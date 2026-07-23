from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


_RANGE_RE = re.compile(r"^([1-9]\d*)-([1-9]\d*)$")


@dataclass(frozen=True)
class LineSpan:
    start: int
    end: int
    raw: int | str


class SpanRelation(str, Enum):
    BEFORE = "before"
    AFTER = "after"
    EQUAL = "equal"
    CONTAINS = "contains"
    CONTAINED = "contained"
    OVERLAP_LEFT = "overlap_left"
    OVERLAP_RIGHT = "overlap_right"


def parse_line(value: object) -> LineSpan:
    """Parse a schema line value without changing its original representation."""
    if isinstance(value, bool):
        raise ValueError("line must not be a boolean")
    if isinstance(value, int):
        if value < 1:
            raise ValueError("integer line must be positive")
        return LineSpan(value, value, value)
    if not isinstance(value, str):
        raise ValueError("line must be a positive integer or a canonical range")
    match = _RANGE_RE.fullmatch(value)
    if not match:
        raise ValueError("range line must use canonical 'start-end' syntax")
    start, end = (int(part) for part in match.groups())
    if start > end:
        raise ValueError("range start must not exceed range end")
    return LineSpan(start, end, value)


def classify_span(span: LineSpan, boundary: LineSpan) -> SpanRelation:
    """Return the inclusive interval relation of span to boundary."""
    if span.end < boundary.start:
        return SpanRelation.BEFORE
    if span.start > boundary.end:
        return SpanRelation.AFTER
    if span.start == boundary.start and span.end == boundary.end:
        return SpanRelation.EQUAL
    if span.start <= boundary.start and span.end >= boundary.end:
        return SpanRelation.CONTAINS
    if span.start >= boundary.start and span.end <= boundary.end:
        return SpanRelation.CONTAINED
    if span.start < boundary.start:
        return SpanRelation.OVERLAP_LEFT
    return SpanRelation.OVERLAP_RIGHT
