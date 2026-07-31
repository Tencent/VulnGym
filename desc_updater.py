"""Description field synchronization — update line/file references in desc."""

from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns for line number references in desc
LINE_REF_PATTERNS = [
    # Chinese: "第 615 行", "第615行", "第 348-352 行"
    (re.compile(r'第\s*(\d+)\s*行'), 'single'),
    (re.compile(r'第\s*(\d+)[–—]\s*(\d+)\s*行'), 'range_ndash'),
    (re.compile(r'第\s*(\d+)\s*-\s*(\d+)\s*行'), 'range_hyphen'),
    # English: "line N", "at line N"
    (re.compile(r'(?<!\w)line\s+(\d+)(?![\d-])', re.IGNORECASE), 'line_single'),
]


class DescUpdater:
    """Updates desc text when node locations change."""

    @staticmethod
    def update_desc(desc: str | None, old_file: str, old_line_start: int, old_line_end: int,
                    new_file: str, new_line_start: int, new_line_end: int) -> Optional[str]:
        """Update desc if file/line references changed. Returns updated desc or None if no change needed."""
        if desc is None:
            return None

        updated = desc
        changed = False

        # Update line references
        if old_line_start != new_line_start or old_line_end != new_line_end:
            new_desc, line_changed = DescUpdater._update_line_refs(
                updated, old_line_start, old_line_end,
                new_line_start, new_line_end
            )
            if line_changed:
                updated = new_desc
                changed = True

        # Update file references
        if old_file != new_file:
            new_desc, file_changed = DescUpdater._update_file_ref(
                updated, old_file, new_file
            )
            if file_changed:
                updated = new_desc
                changed = True

        return updated if changed else None

    @staticmethod
    def _update_line_refs(desc: str, old_start: int, old_end: int,
                          new_start: int, new_end: int) -> tuple[str, bool]:
        """Replace old line numbers with new ones in desc text."""
        changed = False
        result = desc

        for pattern, ptype in LINE_REF_PATTERNS:
            if not changed:
                # Try to find a match that aligns with old values
                for match in pattern.finditer(desc):
                    if ptype == 'single':
                        matched_num = int(match.group(1))
                        if matched_num == old_start:
                            replacement = f"第 {new_start} 行"
                            result = desc[:match.start()] + replacement + desc[match.end():]
                            changed = True
                            break
                    elif ptype in ('range_ndash', 'range_hyphen'):
                        m_start = int(match.group(1))
                        m_end = int(match.group(2))
                        if m_start == old_start and m_end == old_end:
                            if new_start == new_end:
                                replacement = f"第 {new_start} 行"
                            else:
                                replacement = f"第 {new_start}-{new_end} 行"
                            result = desc[:match.start()] + replacement + desc[match.end():]
                            changed = True
                            break
                    elif ptype == 'line_single':
                        matched_num = int(match.group(1))
                        if matched_num == old_start:
                            replacement = f"line {new_start}"
                            result = desc[:match.start()] + replacement + desc[match.end():]
                            changed = True
                            break

        return result, changed

    @staticmethod
    def _update_file_ref(desc: str, old_file: str, new_file: str) -> tuple[str, bool]:
        """Replace old filename references in desc."""
        old_basename = Path(old_file).name
        new_basename = Path(new_file).name

        if old_basename == new_basename:
            return desc, False

        # Check if the old basename appears in desc
        if old_basename in desc:
            return desc.replace(old_basename, new_basename), True

        return desc, False
