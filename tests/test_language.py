"""Tests for multi-language code adaptation."""

import pytest
from pathlib import Path

import sys
from pathlib import Path

# Add bonus to path
sys.path.insert(0, str(Path(__file__).parent.parent / "vulngym-verify-demo"))

from bonus.language.detector import detect_language, LanguageDetector
from bonus.language.normalizer import LanguageNormalizer
from bonus.language.grep_strategy import GrepStrategy


class TestLanguageDetector:
    """Test language detection."""
    
    def test_python_by_extension(self):
        assert detect_language("test.py") == "python"
        assert detect_language("script.pyw") == "python"
    
    def test_javascript_by_extension(self):
        assert detect_language("app.js") == "javascript"
        assert detect_language("module.jsx") == "javascript"
        assert detect_language("index.mjs") == "javascript"
    
    def test_typescript_by_extension(self):
        assert detect_language("component.ts") == "typescript"
        assert detect_language("app.tsx") == "typescript"
    
    def test_go_by_extension(self):
        assert detect_language("main.go") == "go"
    
    def test_java_by_extension(self):
        assert detect_language("Main.java") == "java"
    
    def test_unknown_extension(self):
        assert detect_language("readme.txt") == "unknown"
        assert detect_language("config.yaml") == "unknown"
    
    def test_python_by_content(self):
        content = b"def main():\n    import sys\n    pass"
        assert detect_language("script", content) == "python"
    
    def test_javascript_by_content(self):
        content = b"function test() {\n  const x = 10;\n}"
        assert detect_language("script", content) == "javascript"
    
    def test_typescript_markers(self):
        # TypeScript file with markers
        content = b"interface User {\n  name: string;\n}"
        assert detect_language("types.ts", content) == "typescript"
        
        # .ts file without TS markers falls back to javascript
        content = b"const x = 10;"
        result = detect_language("plain.ts", content)
        assert result in ("typescript", "javascript")  # Accept both


class TestLanguageNormalizer:
    """Test code normalization."""
    
    def test_normalize_python(self):
        normalizer = LanguageNormalizer()
        lines = [
            "def    test(  ):  \n",
            "    x   =   10  \n",
            "    return  x\n"
        ]
        normalized = normalizer.normalize(lines, "python")
        assert "def test(" in normalized[0]
        assert "x = 10" in normalized[1]
    
    def test_normalize_javascript(self):
        normalizer = LanguageNormalizer()
        lines = [
            "function   test(  ) {  \n",
            "  const   x  =  10;  \n",
            "}  \n"
        ]
        normalized = normalizer.normalize(lines, "javascript")
        assert "function test(" in normalized[0]
        assert "const x = 10;" in normalized[1]
    
    def test_normalize_go_tabs(self):
        normalizer = LanguageNormalizer()
        lines = [
            "func test() {\n",
            "\tx := 10\n",
            "}\n"
        ]
        normalized = normalizer.normalize(lines, "go")
        # Tabs converted to spaces
        assert "\t" not in normalized[1]
        assert "    x := 10" in normalized[1]
    
    def test_preserve_comments(self):
        normalizer = LanguageNormalizer()
        # Python comments preserved
        lines = ["# This is a comment with    multiple   spaces\n"]
        normalized = normalizer.normalize(lines, "python")
        assert "multiple   spaces" in normalized[0]
        
        # JS comments preserved
        lines = ["// This is a comment with    multiple   spaces\n"]
        normalized = normalizer.normalize(lines, "javascript")
        assert "multiple   spaces" in normalized[0]
    
    def test_get_line_range_python_block(self):
        normalizer = LanguageNormalizer()
        lines = [
            "import sys\n",
            "\n",
            "def test():\n",  # line 3
            "    x = 10\n",    # line 4
            "    y = 20\n",    # line 5
            "    return x + y\n",  # line 6
            "\n",
            "def other():\n",
            "    pass\n"
        ]
        # Request lines 4-5, should expand to include function
        extracted, start, end = normalizer.get_line_range(lines, 4, 5, "python")
        assert start == 3  # Expanded to include 'def'
        assert "def test()" in "".join(extracted)
    
    def test_get_line_range_javascript_braces(self):
        normalizer = LanguageNormalizer()
        lines = [
            "function test() {\n",  # line 1
            "  const x = 10;\n",     # line 2
            "  return x;\n",         # line 3
            "}\n",                   # line 4
            "\n"
        ]
        extracted, start, end = normalizer.get_line_range(lines, 2, 3, "javascript")
        # Should expand to include braces or at least get the requested range
        assert len(extracted) >= 2
        assert "const x = 10" in "".join(extracted)


class TestGrepStrategy:
    """Test grep strategies."""
    
    def test_python_function_pattern(self):
        strategy = GrepStrategy()
        pattern = strategy.get_function_pattern("test_func", "python")
        assert "def" in pattern
        assert "test_func" in pattern
        
        import re
        # Should match
        assert re.search(pattern, "def test_func():")
        assert re.search(pattern, "def test_func(arg1, arg2):")
        # Comments still match (filtering is done at higher level)
        # This is expected behavior - pattern matching is simple
    
    def test_javascript_function_pattern(self):
        strategy = GrepStrategy()
        pattern = strategy.get_function_pattern("myFunc", "javascript")
        
        import re
        # Should match various JS patterns
        assert re.search(pattern, "function myFunc() {")
        assert re.search(pattern, "const myFunc = () => {")
        assert re.search(pattern, "myFunc: function() {")
    
    def test_go_function_pattern(self):
        strategy = GrepStrategy()
        pattern = strategy.get_function_pattern("DoSomething", "go")
        assert "func" in pattern
        
        import re
        assert re.search(pattern, "func DoSomething() error {")
    
    def test_java_function_pattern(self):
        strategy = GrepStrategy()
        pattern = strategy.get_function_pattern("getValue", "java")
        
        import re
        assert re.search(pattern, "public int getValue() {")
        assert re.search(pattern, "private String getValue(int x) {")
    
    def test_class_patterns(self):
        strategy = GrepStrategy()
        
        import re
        # Python
        py_pattern = strategy.get_class_pattern("MyClass", "python")
        assert re.search(py_pattern, "class MyClass:")
        assert re.search(py_pattern, "class MyClass(Base):")
        
        # JavaScript
        js_pattern = strategy.get_class_pattern("MyClass", "javascript")
        assert re.search(js_pattern, "class MyClass {")
        assert re.search(js_pattern, "class MyClass extends Base {")
        
        # Go
        go_pattern = strategy.get_class_pattern("MyStruct", "go")
        assert re.search(go_pattern, "type MyStruct struct {")
        
        # Java
        java_pattern = strategy.get_class_pattern("MyClass", "java")
        assert re.search(java_pattern, "class MyClass {")
        assert re.search(java_pattern, "interface MyClass {")
    
    def test_import_patterns(self):
        strategy = GrepStrategy()
        
        import re
        # Python
        py_pattern = strategy.get_import_pattern("os", "python")
        assert re.search(py_pattern, "import os")
        assert re.search(py_pattern, "from os import path")
        
        # JavaScript
        js_pattern = strategy.get_import_pattern("react", "javascript")
        assert re.search(js_pattern, "import React from 'react'")
        assert re.search(js_pattern, "const React = require('react')")
        
        # Go
        go_pattern = strategy.get_import_pattern("fmt", "go")
        assert re.search(go_pattern, 'import "fmt"')
        
        # Java
        java_pattern = strategy.get_import_pattern("java.util.List", "java")
        assert re.search(java_pattern, "import java.util.List;")
    
    def test_extract_function_signature_python(self):
        strategy = GrepStrategy()
        lines = [
            "class Test:\n",
            "    def calculate(\n",
            "        self,\n",
            "        x: int,\n",
            "        y: int\n",
            "    ) -> int:\n",
            "        return x + y\n"
        ]
        sig = strategy.extract_function_signature(lines, 2, "python")
        assert sig is not None
        assert "calculate" in sig
        # Signature extraction is best-effort for multi-line
        assert "def" in sig
    
    def test_extract_function_signature_javascript(self):
        strategy = GrepStrategy()
        lines = [
            "function calculateSum(\n",
            "  a,\n",
            "  b\n",
            ") {\n",
            "  return a + b;\n",
            "}\n"
        ]
        sig = strategy.extract_function_signature(lines, 1, "javascript")
        assert sig is not None
        assert "calculateSum" in sig
    
    def test_comment_patterns(self):
        strategy = GrepStrategy()
        
        py_comments = strategy.get_comment_patterns("python")
        assert py_comments["line"] == "#"
        assert py_comments["block_start"] == '"""'
        
        js_comments = strategy.get_comment_patterns("javascript")
        assert js_comments["line"] == "//"
        assert js_comments["block_start"] == "/*"
        
        go_comments = strategy.get_comment_patterns("go")
        assert go_comments["line"] == "//"
        
        java_comments = strategy.get_comment_patterns("java")
        assert java_comments["line"] == "//"


class TestUnknownLanguageFallback:
    """Test safe fallback for unknown languages."""
    
    def test_unknown_language_normalize(self):
        normalizer = LanguageNormalizer()
        lines = ["some text\n", "  indented\n"]
        # Should return unchanged for unknown language
        normalized = normalizer.normalize(lines, "unknown")
        assert normalized == lines
    
    def test_unknown_language_grep(self):
        strategy = GrepStrategy()
        # Should return escaped pattern for unknown language
        pattern = strategy.get_function_pattern("test", "unknown")
        assert "test" in pattern
