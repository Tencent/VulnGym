"""Code matching engine: normalize, search, and disambiguate."""

from __future__ import annotations

import re
import logging
from typing import Optional

from .loader import normalize_line
from .models import MatchResult
from .repo_manager import RepoManager

logger = logging.getLogger(__name__)

# Patterns for generic/unmatchable code detection
_DOCKER_PATTERN = re.compile(
    r'^\s*(FROM|RUN|CMD|ENTRYPOINT|WORKDIR|COPY|ADD|EXPOSE|ENV|ARG|LABEL|VOLUME|USER)\s',
    re.IGNORECASE
)
_TRUNCATED_SIG = re.compile(r'^.*\($')  # ends with '(' on a single line

# Min meaningful code length after normalization
MIN_CODE_LENGTH = 5


class CodeMatcher:
    """Searches for code snippets in source repos with cascading strategies."""

    def __init__(self, repo_mgr: RepoManager):
        self.repo_mgr = repo_mgr
        self._norm_cache: dict[int, str] = {}  # id(code) → normalized

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_node(self, entry_id: str, node_path: str,
                   node: dict, repo_url: str, commit: str) -> MatchResult:
        """Check a single node against the source repo. Returns MatchResult."""
        file = node.get("file", "")
        code = node.get("code", "")
        desc = node.get("desc")
        try:
            line_range = normalize_line(node.get("line", 1))
        except (ValueError, TypeError):
            line_range = (1, 1)
        line_raw = node.get("line", 1)

        result = MatchResult(
            entry_id=entry_id,
            node_path=node_path,
            original_file=file,
            original_line_raw=line_raw,
            original_line_range=line_range,
            original_code=code,
            original_desc=desc,
        )

        # Step 0: Precheck
        precheck_reason = self._precheck(code)
        if precheck_reason:
            result.status = "needs_human"
            result.needs_human_reason = precheck_reason
            return result

        # Ensure repo is available
        if not self.repo_mgr.repo_available(repo_url):
            result.status = "needs_human"
            result.needs_human_reason = "REPO_UNAVAILABLE"
            return result

        norm_code = self._normalize_code(code)
        norm_lines = norm_code.split("\n")

        # Step 1: Exact match at claimed location
        content = self.repo_mgr.get_file_content(repo_url, commit, file)
        if content is None:
            # File not found — skip to repo-wide search
            pass
        else:
            file_lines = content.split("\n")

            # Check if code matches at the claimed line range
            start, end = line_range
            if self._match_at(file_lines, norm_lines, start - 1, 0):
                result.status = "exact_match"
                result.strategy = "exact"
                result.match_count = 1
                return result

            # Step 2: Search ±5 lines around claimed location
            nearby = self._search_nearby(file_lines, norm_lines, start, radius=5)
            if len(nearby) == 1:
                new_start = nearby[0]
                result.status = "fixed_line"
                result.strategy = "nearby_5"
                result.match_count = 1
                result.new_file = file
                result.new_line_range = (new_start, new_start + len(norm_lines) - 1)
                return result

            # Step 3: File-wide search
            file_wide = self._search_file_wide(file_lines, norm_lines)
            if len(file_wide) == 1:
                new_start = file_wide[0]
                result.status = "fixed_line"
                result.strategy = "file_wide"
                result.match_count = 1
                result.new_file = file
                result.new_line_range = (new_start, new_start + len(norm_lines) - 1)
                return result
            elif len(file_wide) > 1:
                # Step 4: Context disambiguation
                disambig = self._context_disambiguate(file_wide, norm_lines, file_lines)
                if disambig is not None:
                    result.status = "fixed_line"
                    result.strategy = "context_disambig"
                    result.match_count = 1
                    result.new_file = file
                    result.new_line_range = (disambig, disambig + len(norm_lines) - 1)
                    return result
                else:
                    result.status = "needs_human"
                    result.needs_human_reason = "MULTIPLE_MATCHES"
                    result.match_count = len(file_wide)
                    result.candidates = [(file, n) for n in file_wide]
                    result.detail = f"{len(file_wide)} matches in {file}"
                    return result

        # Step 5: Repo-wide search
        if norm_lines:
            first_line = norm_lines[0].strip()
            if first_line:
                repo_matches = self.repo_mgr.git_grep(repo_url, commit, first_line)
                # Filter: verify full multi-line match
                verified = self._verify_repo_matches(
                    repo_url, commit, repo_matches, norm_lines
                )
                if len(verified) == 1:
                    new_file, new_start = verified[0]
                    result.status = "fixed_file"
                    result.strategy = "repo_wide"
                    result.match_count = 1
                    result.new_file = new_file
                    result.new_line_range = (new_start, new_start + len(norm_lines) - 1)
                    return result
                elif len(verified) > 1:
                    result.status = "needs_human"
                    result.needs_human_reason = "MULTIPLE_MATCHES"
                    result.match_count = len(verified)
                    result.candidates = verified
                    result.detail = f"{len(verified)} matches in repo"
                    return result

        # Not found anywhere
        result.status = "needs_human"
        result.needs_human_reason = "NO_MATCH"
        return result

    # ------------------------------------------------------------------
    # Precheck
    # ------------------------------------------------------------------

    def _precheck(self, code: str) -> str:
        """Check if code is unmatchable. Returns reason string or ''."""
        if not code or not code.strip():
            return "EMPTY_CODE"

        norm = self._normalize_code(code)
        stripped = norm.strip()

        # Only punctuation / braces
        if re.fullmatch(r'[\s\{\}\(\)\[\];,.\-+=*/<>!@#$%^&|~`]+', stripped):
            return "UNMATCHABLE_CODE"

        # Too short
        if len(stripped) < MIN_CODE_LENGTH:
            return "UNMATCHABLE_CODE"

        # Truncated signature: single line ending with '('
        single_line = stripped.replace("\n", " ").strip()
        if _TRUNCATED_SIG.match(single_line) and ")" not in single_line:
            return "TRUNCATED_CODE"

        # Docker instruction
        if _DOCKER_PATTERN.match(stripped):
            return "UNMATCHABLE_CODE"

        # Generic single-statement patterns
        lower = stripped.lower()
        if lower in ("return false;", "return true;", "return;", "return null;",
                      "return nil;", "break;", "continue;", "pass", "};", "]);", ");"):
            return "UNMATCHABLE_CODE"

        return ""

    # ------------------------------------------------------------------
    # Code normalization
    # ------------------------------------------------------------------

    def _normalize_code(self, code: str) -> str:
        """Normalize code for comparison."""
        cache_key = id(code)
        if cache_key in self._norm_cache:
            return self._norm_cache[cache_key]

        lines = code.split("\n")
        result_lines = []

        for line in lines:
            # Strip trailing whitespace only (preserve indentation intent)
            stripped = line.rstrip()
            # Normalize tabs to spaces (tab = 1 space for matching)
            no_tabs = stripped.replace("\t", " ")
            result_lines.append(no_tabs)

        # Remove leading/trailing empty lines
        while result_lines and not result_lines[0].strip():
            result_lines.pop(0)
        while result_lines and not result_lines[-1].strip():
            result_lines.pop()

        result = "\n".join(result_lines)
        self._norm_cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Search strategies
    # ------------------------------------------------------------------

    def _match_at(self, file_lines: list[str], norm_lines: list[str],
                  start_idx: int, tolerance: int = 0) -> bool:
        """Check if norm_lines appear in file_lines starting at start_idx."""
        if not norm_lines:
            return False
        comp_lines = [self._normalize_line_for_compare(l) for l in file_lines]
        nl = [self._normalize_line_for_compare(l) for l in norm_lines]

        for offset in range(-tolerance, tolerance + 1):
            idx = start_idx + offset
            if idx < 0 or idx + len(nl) > len(comp_lines):
                continue
            if all(comp_lines[idx + i] == nl[i] for i in range(len(nl))):
                return True
        return False

    def _search_nearby(self, file_lines: list[str], norm_lines: list[str],
                       center: int, radius: int = 5) -> list[int]:
        """Search for norm_lines within ±radius of center. Returns list of 1-based start lines."""
        comp_lines = [self._normalize_line_for_compare(l) for l in file_lines]
        nl = [self._normalize_line_for_compare(l) for l in norm_lines]

        matches = []
        search_start = max(0, center - 1 - radius)
        search_end = min(len(comp_lines), center - 1 + radius + len(nl))

        for i in range(search_start, search_end - len(nl) + 1):
            if all(comp_lines[i + j] == nl[j] for j in range(len(nl))):
                matches.append(i + 1)  # 1-based
        return matches

    def _search_file_wide(self, file_lines: list[str],
                          norm_lines: list[str]) -> list[int]:
        """Search entire file for norm_lines. Returns list of 1-based start lines."""
        comp_lines = [self._normalize_line_for_compare(l) for l in file_lines]
        nl = [self._normalize_line_for_compare(l) for l in norm_lines]

        matches = []
        for i in range(len(comp_lines) - len(nl) + 1):
            if all(comp_lines[i + j] == nl[j] for j in range(len(nl))):
                matches.append(i + 1)
        return matches

    def _context_disambiguate(self, matches: list[int], norm_lines: list[str],
                              file_lines: list[str]) -> Optional[int]:
        """Try to pick the right match using context clues.

        For multi-line code, check if the surrounding lines provide unique context.
        """
        if len(matches) == 1:
            return matches[0]
        # For now, we can't disambiguate without additional context
        # Future: use other trace nodes' file/line info
        return None

    def _verify_repo_matches(self, repo_url: str, commit: str,
                             candidates: list[tuple[str, int]],
                             norm_lines: list[str]) -> list[tuple[str, int]]:
        """Verify multi-line matches from repo-wide grep results."""
        verified = []
        for file_path, line_num in candidates:
            content = self.repo_mgr.get_file_content(repo_url, commit, file_path)
            if content is None:
                continue
            file_lines = content.split("\n")
            comp_lines = [self._normalize_line_for_compare(l) for l in file_lines]
            nl = [self._normalize_line_for_compare(l) for l in norm_lines]

            idx = line_num - 1
            if idx + len(nl) <= len(comp_lines):
                if all(comp_lines[idx + j] == nl[j] for j in range(len(nl))):
                    verified.append((file_path, line_num))
        return verified

    @staticmethod
    def _normalize_line_for_compare(line: str) -> str:
        """Normalize a single line for comparison: strip, collapse whitespace."""
        return re.sub(r'\s+', ' ', line.rstrip()).strip()

    # ------------------------------------------------------------------
    # Structural checks (trace self-referencing)
    # ------------------------------------------------------------------

    @staticmethod
    def check_self_reference(entry_point: dict, critical_operation: dict,
                             trace: list[dict]) -> tuple[bool, str]:
        """Check if trace[0] or trace[-1] self-references entry/critical nodes."""
        if not trace:
            return False, ""

        ep_key = (entry_point.get("file", ""),
                  normalize_line(entry_point.get("line", 1)))
        co_key = (critical_operation.get("file", ""),
                  normalize_line(critical_operation.get("line", 1)))

        issues = []

        t0 = trace[0]
        t0_key = (t0.get("file", ""), normalize_line(t0.get("line", 1)))
        if t0_key == ep_key:
            issues.append("trace_starts_at_entry")

        t_last = trace[-1]
        t_last_key = (t_last.get("file", ""), normalize_line(t_last.get("line", 1)))
        if t_last_key == co_key:
            issues.append("trace_ends_at_critical")

        if not issues:
            return False, ""
        return True, "|".join(issues)
