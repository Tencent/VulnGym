"""Language detection based on file extensions and content patterns."""

from pathlib import Path
from typing import Literal, Optional

LanguageType = Literal["python", "javascript", "typescript", "go", "java", "unknown"]


class LanguageDetector:
    """Detect programming language from file path and content."""
    
    # Extension mappings
    EXTENSION_MAP = {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
    }
    
    # Content-based patterns for ambiguous cases
    CONTENT_PATTERNS = {
        "python": [b"def ", b"import ", b"class ", b"from "],
        "javascript": [b"function ", b"const ", b"let ", b"var "],
        "typescript": [b"interface ", b"type ", b": string", b": number"],
        "go": [b"package ", b"func ", b"import ("],
        "java": [b"public class ", b"private ", b"import java."],
    }
    
    def detect(self, file_path: str, content: Optional[bytes] = None) -> LanguageType:
        """
        Detect language from file path and optionally content.
        
        Args:
            file_path: Path to the file
            content: Optional file content for ambiguous cases
            
        Returns:
            Detected language type
        """
        # Try extension-based detection first
        ext = Path(file_path).suffix.lower()
        if ext in self.EXTENSION_MAP:
            lang = self.EXTENSION_MAP[ext]
            # For TypeScript, double-check content if available
            if lang == "typescript" and content:
                if not self._has_typescript_markers(content):
                    return "javascript"
            return lang
        
        # Fallback to content-based detection
        if content:
            return self._detect_from_content(content)
        
        return "unknown"
    
    def _detect_from_content(self, content: bytes) -> LanguageType:
        """Detect language from content patterns."""
        scores = {lang: 0 for lang in ["python", "javascript", "typescript", "go", "java"]}
        
        for lang, patterns in self.CONTENT_PATTERNS.items():
            for pattern in patterns:
                if pattern in content:
                    scores[lang] += 1
        
        max_score = max(scores.values())
        if max_score == 0:
            return "unknown"
        
        # Return language with highest score
        for lang, score in scores.items():
            if score == max_score:
                return lang
        
        return "unknown"
    
    def _has_typescript_markers(self, content: bytes) -> bool:
        """Check if content has TypeScript-specific markers."""
        ts_markers = [b"interface ", b"type ", b": string", b": number", b"<T>", b"as "]
        return any(marker in content for marker in ts_markers)


# Singleton instance
_detector = LanguageDetector()


def detect_language(file_path: str, content: Optional[bytes] = None) -> LanguageType:
    """
    Convenience function to detect language.
    
    Args:
        file_path: Path to the file
        content: Optional file content
        
    Returns:
        Detected language type
        
    Example:
        >>> detect_language("example.py")
        'python'
        >>> detect_language("main.go")
        'go'
    """
    return _detector.detect(file_path, content)
