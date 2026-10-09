"""Code normalization for consistent line handling across languages."""

from typing import List, Tuple
from .detector import LanguageType


class LanguageNormalizer:
    """Normalize code lines based on language-specific rules."""
    
    def normalize(self, lines: List[str], language: LanguageType) -> List[str]:
        """
        Normalize code lines for consistent processing.
        
        Args:
            lines: Raw code lines
            language: Detected language type
            
        Returns:
            Normalized lines with consistent indentation and whitespace
        """
        if language == "unknown":
            return lines
        
        normalized = []
        for line in lines:
            # Strip trailing whitespace but preserve leading
            norm_line = line.rstrip()
            
            # Language-specific normalizations
            if language == "python":
                norm_line = self._normalize_python(norm_line)
            elif language in ("javascript", "typescript"):
                norm_line = self._normalize_js(norm_line)
            elif language == "go":
                norm_line = self._normalize_go(norm_line)
            elif language == "java":
                norm_line = self._normalize_java(norm_line)
            
            normalized.append(norm_line)
        
        return normalized
    
    def _normalize_python(self, line: str) -> str:
        """Python-specific normalization."""
        # Preserve indentation, normalize multiple spaces in code
        stripped = line.lstrip()
        if not stripped:
            return ""
        indent = line[:len(line) - len(stripped)]
        # Don't normalize strings
        if '"""' in stripped or "'''" in stripped or stripped.startswith("#"):
            return line.rstrip()
        return indent + " ".join(stripped.split())
    
    def _normalize_js(self, line: str) -> str:
        """JavaScript/TypeScript normalization."""
        stripped = line.lstrip()
        if not stripped:
            return ""
        # Preserve indentation
        indent = line[:len(line) - len(stripped)]
        # Don't normalize comments or strings
        if stripped.startswith("//") or stripped.startswith("/*"):
            return line.rstrip()
        return indent + " ".join(stripped.split())
    
    def _normalize_go(self, line: str) -> str:
        """Go normalization (tabs to spaces for consistency)."""
        # Convert tabs to 4 spaces for uniform processing
        line = line.replace("\t", "    ")
        return line.rstrip()
    
    def _normalize_java(self, line: str) -> str:
        """Java normalization."""
        stripped = line.lstrip()
        if not stripped:
            return ""
        indent = line[:len(line) - len(stripped)]
        # Don't normalize comments
        if stripped.startswith("//") or stripped.startswith("/*"):
            return line.rstrip()
        return indent + " ".join(stripped.split())
    
    def get_line_range(
        self,
        lines: List[str],
        start: int,
        end: int,
        language: LanguageType
    ) -> Tuple[List[str], int, int]:
        """
        Extract line range with language-aware context expansion.
        
        Args:
            lines: All file lines
            start: Start line (1-indexed)
            end: End line (1-indexed, inclusive)
            language: Detected language
            
        Returns:
            (extracted_lines, actual_start, actual_end)
        """
        # Convert to 0-indexed
        start_idx = max(0, start - 1)
        end_idx = min(len(lines), end)
        
        # Expand to include full statement/block if needed
        if language == "python":
            start_idx, end_idx = self._expand_python_block(lines, start_idx, end_idx)
        elif language in ("javascript", "typescript", "java"):
            start_idx, end_idx = self._expand_brace_block(lines, start_idx, end_idx)
        elif language == "go":
            start_idx, end_idx = self._expand_go_block(lines, start_idx, end_idx)
        
        extracted = lines[start_idx:end_idx]
        return extracted, start_idx + 1, end_idx
    
    def _expand_python_block(self, lines: List[str], start: int, end: int) -> Tuple[int, int]:
        """Expand to include complete Python indented block."""
        if start >= len(lines):
            return start, end
        
        # Find base indentation
        base_indent = len(lines[start]) - len(lines[start].lstrip())
        
        # Expand backward to include def/class
        new_start = start
        for i in range(start - 1, max(0, start - 5), -1):
            line = lines[i]
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent < base_indent and ("def " in line or "class " in line):
                new_start = i
                break
        
        # Expand forward to include full block
        new_end = end
        for i in range(end, min(len(lines), end + 5)):
            line = lines[i]
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                break
            new_end = i + 1
        
        return new_start, new_end
    
    def _expand_brace_block(self, lines: List[str], start: int, end: int) -> Tuple[int, int]:
        """Expand to include complete brace-delimited block."""
        # Simple heuristic: include surrounding braces
        new_start = start
        new_end = end
        
        # Look for opening brace before start
        for i in range(start - 1, max(0, start - 3), -1):
            if "{" in lines[i]:
                new_start = i
                break
        
        # Look for closing brace after end
        for i in range(end, min(len(lines), end + 3)):
            if "}" in lines[i]:
                new_end = i + 1
                break
        
        return new_start, new_end
    
    def _expand_go_block(self, lines: List[str], start: int, end: int) -> Tuple[int, int]:
        """Expand to include complete Go function/block."""
        return self._expand_brace_block(lines, start, end)


# Singleton instance
_normalizer = LanguageNormalizer()


def normalize_code(lines: List[str], language: LanguageType) -> List[str]:
    """
    Convenience function to normalize code lines.
    
    Args:
        lines: Raw code lines
        language: Detected language type
        
    Returns:
        Normalized lines
    """
    return _normalizer.normalize(lines, language)
