"""Demo script for multi-language code adaptation."""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bonus.language import detect_language, normalize_code, get_grep_strategy
from bonus.language.normalizer import LanguageNormalizer


def demo_language_detection():
    """Demonstrate language detection across file types."""
    print("=" * 70)
    print("DEMO 1: Language Detection")
    print("=" * 70)
    
    test_files = [
        ("example.py", b"def main():\n    import os\n"),
        ("app.js", b"function test() {\n  const x = 10;\n}"),
        ("main.go", b"package main\n\nfunc main() {\n}"),
        ("Main.java", b"public class Main {\n  public static void main() {\n  }\n}"),
        ("config.ts", b"interface Config {\n  port: number;\n}"),
        ("unknown.txt", b"some text"),
    ]
    
    for filename, content in test_files:
        lang = detect_language(filename, content)
        print(f"\n{filename:20} -> {lang:15}")
        if content:
            print(f"  Content preview: {content[:50].decode('utf-8', errors='ignore')!r}")
    
    print("\n" + "=" * 70 + "\n")


def demo_code_normalization():
    """Demonstrate code normalization."""
    print("=" * 70)
    print("DEMO 2: Code Normalization")
    print("=" * 70)
    
    # Python example
    print("\n[Python Code]")
    py_lines = [
        "def    calculate(  x,   y  ):  \n",
        "    result   =   x   +   y  \n",
        "    return  result\n"
    ]
    print("Original:")
    for line in py_lines:
        print(f"  {line!r}")
    
    normalized = normalize_code(py_lines, "python")
    print("\nNormalized:")
    for line in normalized:
        print(f"  {line!r}")
    
    # JavaScript example
    print("\n[JavaScript Code]")
    js_lines = [
        "function   test(  ) {  \n",
        "  const   x  =  10;  \n",
        "  return   x;  \n",
        "}  \n"
    ]
    print("Original:")
    for line in js_lines:
        print(f"  {line!r}")
    
    normalized = normalize_code(js_lines, "javascript")
    print("\nNormalized:")
    for line in normalized:
        print(f"  {line!r}")
    
    # Go example (tab conversion)
    print("\n[Go Code - Tab Conversion]")
    go_lines = [
        "func main() {\n",
        "\tx := 10\n",
        "\ty := 20\n",
        "}\n"
    ]
    print("Original (with tabs):")
    for line in go_lines:
        print(f"  {line!r}")
    
    normalized = normalize_code(go_lines, "go")
    print("\nNormalized (tabs -> spaces):")
    for line in normalized:
        print(f"  {line!r}")
    
    print("\n" + "=" * 70 + "\n")


def demo_function_search():
    """Demonstrate language-specific function search patterns."""
    print("=" * 70)
    print("DEMO 3: Language-Specific Function Search")
    print("=" * 70)
    
    strategy = get_grep_strategy()
    
    languages = ["python", "javascript", "go", "java"]
    function_name = "calculateSum"
    
    for lang in languages:
        pattern = strategy.get_function_pattern(function_name, lang)
        print(f"\n[{lang.upper()}]")
        print(f"  Function: {function_name}")
        print(f"  Pattern:  {pattern}")
        
        # Show example matches
        if lang == "python":
            examples = [
                "def calculateSum(a, b):",
                "    def calculateSum(x):",
            ]
        elif lang == "javascript":
            examples = [
                "function calculateSum(a, b) {",
                "const calculateSum = (a, b) => {",
                "calculateSum: function(a, b) {",
            ]
        elif lang == "go":
            examples = [
                "func calculateSum(a int, b int) int {",
            ]
        else:  # java
            examples = [
                "public int calculateSum(int a, int b) {",
                "private double calculateSum(double x) {",
            ]
        
        print("  Matches:")
        import re
        for ex in examples:
            if re.search(pattern, ex):
                print(f"    [+] {ex}")
    
    print("\n" + "=" * 70 + "\n")


def demo_context_expansion():
    """Demonstrate language-aware context expansion."""
    print("=" * 70)
    print("DEMO 4: Language-Aware Context Expansion")
    print("=" * 70)
    
    normalizer = LanguageNormalizer()
    
    # Python example
    print("\n[Python - Block Expansion]")
    py_code = [
        "import sys\n",
        "\n",
        "def calculate(x, y):\n",
        "    # Main calculation\n",
        "    result = x + y\n",
        "    return result\n",
        "\n",
        "def other():\n",
        "    pass\n"
    ]
    print("Full code:")
    for i, line in enumerate(py_code, 1):
        print(f"  {i:2}: {line.rstrip()}")
    
    # Request lines 4-5, should expand to include function
    extracted, start, end = normalizer.get_line_range(py_code, 4, 5, "python")
    print(f"\nRequested: lines 4-5")
    print(f"Expanded:  lines {start}-{end}")
    print("Extracted:")
    for line in extracted:
        print(f"  {line.rstrip()}")
    
    # JavaScript example
    print("\n[JavaScript - Brace Expansion]")
    js_code = [
        "function test() {\n",
        "  const x = 10;\n",
        "  const y = 20;\n",
        "  return x + y;\n",
        "}\n",
    ]
    print("Full code:")
    for i, line in enumerate(js_code, 1):
        print(f"  {i:2}: {line.rstrip()}")
    
    extracted, start, end = normalizer.get_line_range(js_code, 2, 3, "javascript")
    print(f"\nRequested: lines 2-3")
    print(f"Expanded:  lines {start}-{end}")
    print("Extracted:")
    for line in extracted:
        print(f"  {line.rstrip()}")
    
    print("\n" + "=" * 70 + "\n")


def demo_unknown_language_safety():
    """Demonstrate safe fallback for unknown languages."""
    print("=" * 70)
    print("DEMO 5: Safe Fallback for Unknown Languages")
    print("=" * 70)
    
    print("\n[Unknown Language Detection]")
    unknown_files = [
        ("config.yaml", b"key: value\n"),
        ("data.json", b'{"key": "value"}'),
        ("README.md", b"# Title\n"),
    ]
    
    for filename, content in unknown_files:
        lang = detect_language(filename, content)
        print(f"  {filename:20} -> {lang}")
    
    print("\n[Safe Normalization - No Changes]")
    unknown_lines = ["some text\n", "  indented\n", "no changes\n"]
    normalized = normalize_code(unknown_lines, "unknown")
    
    print("Original:")
    for line in unknown_lines:
        print(f"  {line!r}")
    
    print("\nAfter 'normalization' (unchanged):")
    for line in normalized:
        print(f"  {line!r}")
    
    print("\n[+] Unknown languages safely pass through unchanged")
    print("[+] No errors or exceptions raised")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """Run all demos."""
    print("\n")
    print("+" + "=" * 68 + "+")
    print("|" + " " * 10 + "VulnGym Multi-Language Code Adaptation Demo" + " " * 15 + "|")
    print("+" + "=" * 68 + "+")
    print()
    
    demo_language_detection()
    demo_code_normalization()
    demo_function_search()
    demo_context_expansion()
    demo_unknown_language_safety()
    
    print("+" + "=" * 68 + "+")
    print("|" + " " * 25 + "Demo Complete!" + " " * 28 + "|")
    print("+" + "=" * 68 + "+")
    print()


if __name__ == "__main__":
    main()
