"""
Multi-language code adaptation module for VulnGym.

Provides language-specific strategies for:
- Language detection (Python/JS/Go/Java)
- Line reading and normalization
- Code search patterns
- Safe fallback for unsupported languages
"""

from .detector import LanguageDetector, detect_language
from .normalizer import LanguageNormalizer, normalize_code
from .grep_strategy import GrepStrategy, get_grep_strategy

__all__ = [
    "LanguageDetector",
    "detect_language",
    "LanguageNormalizer", 
    "normalize_code",
    "GrepStrategy",
    "get_grep_strategy",
]
