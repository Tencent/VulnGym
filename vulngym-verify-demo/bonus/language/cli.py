"""CLI for multi-language code adaptation tools."""

import sys
import json
from pathlib import Path
from typing import Optional

from .detector import detect_language, LanguageType
from .normalizer import LanguageNormalizer
from .grep_strategy import GrepStrategy


def cmd_detect(file_path: str) -> dict:
    """Detect language of a file."""
    content = None
    if Path(file_path).exists():
        with open(file_path, "rb") as f:
            content = f.read()
    
    lang = detect_language(file_path, content)
    return {
        "file": file_path,
        "language": lang,
        "confidence": "high" if content else "filename_only"
    }


def cmd_normalize(file_path: str, language: Optional[LanguageType] = None) -> dict:
    """Normalize code in a file."""
    if not Path(file_path).exists():
        return {"error": f"File not found: {file_path}"}
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    if language is None:
        language = detect_language(file_path)
    
    normalizer = LanguageNormalizer()
    normalized = normalizer.normalize(lines, language)
    
    return {
        "file": file_path,
        "language": language,
        "original_lines": len(lines),
        "normalized_lines": len(normalized),
        "sample": normalized[:5] if normalized else []
    }


def cmd_search_function(file_path: str, function_name: str, language: Optional[LanguageType] = None) -> dict:
    """Search for function definition."""
    if not Path(file_path).exists():
        return {"error": f"File not found: {file_path}"}
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    if language is None:
        language = detect_language(file_path)
    
    strategy = GrepStrategy()
    pattern = strategy.get_function_pattern(function_name, language)
    
    import re
    matches = []
    for i, line in enumerate(lines, 1):
        if re.search(pattern, line):
            sig = strategy.extract_function_signature(lines, i, language)
            matches.append({
                "line": i,
                "content": line.strip(),
                "signature": sig
            })
    
    return {
        "file": file_path,
        "language": language,
        "function": function_name,
        "pattern": pattern,
        "matches": matches
    }


def cmd_get_line_range(
    file_path: str,
    start: int,
    end: int,
    language: Optional[LanguageType] = None
) -> dict:
    """Get line range with language-aware expansion."""
    if not Path(file_path).exists():
        return {"error": f"File not found: {file_path}"}
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    if language is None:
        language = detect_language(file_path)
    
    normalizer = LanguageNormalizer()
    extracted, actual_start, actual_end = normalizer.get_line_range(
        lines, start, end, language
    )
    
    return {
        "file": file_path,
        "language": language,
        "requested": {"start": start, "end": end},
        "actual": {"start": actual_start, "end": actual_end},
        "lines": [line.rstrip() for line in extracted]
    }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Multi-language code adaptation tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect language
  python -m bonus.language.cli detect example.py
  
  # Normalize code
  python -m bonus.language.cli normalize src/main.go
  
  # Search for function
  python -m bonus.language.cli search-function utils.js readFile
  
  # Get line range with context
  python -m bonus.language.cli get-range main.py 10 15
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # detect command
    detect_parser = subparsers.add_parser("detect", help="Detect file language")
    detect_parser.add_argument("file", help="File path")
    
    # normalize command
    norm_parser = subparsers.add_parser("normalize", help="Normalize code")
    norm_parser.add_argument("file", help="File path")
    norm_parser.add_argument("--lang", help="Override language detection")
    
    # search-function command
    search_parser = subparsers.add_parser("search-function", help="Search for function")
    search_parser.add_argument("file", help="File path")
    search_parser.add_argument("function", help="Function name")
    search_parser.add_argument("--lang", help="Override language detection")
    
    # get-range command
    range_parser = subparsers.add_parser("get-range", help="Get line range")
    range_parser.add_argument("file", help="File path")
    range_parser.add_argument("start", type=int, help="Start line (1-indexed)")
    range_parser.add_argument("end", type=int, help="End line (1-indexed)")
    range_parser.add_argument("--lang", help="Override language detection")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    result = {}
    
    try:
        if args.command == "detect":
            result = cmd_detect(args.file)
        elif args.command == "normalize":
            result = cmd_normalize(args.file, args.lang)
        elif args.command == "search-function":
            result = cmd_search_function(args.file, args.function, args.lang)
        elif args.command == "get-range":
            result = cmd_get_line_range(args.file, args.start, args.end, args.lang)
        
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if "error" not in result else 1
        
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
