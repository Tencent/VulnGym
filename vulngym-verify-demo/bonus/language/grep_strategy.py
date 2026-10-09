"""Language-specific grep strategies for code search."""

import re
from typing import List, Dict, Any, Optional
from .detector import LanguageType


class GrepStrategy:
    """Language-specific strategies for code search."""
    
    def get_function_pattern(self, function_name: str, language: LanguageType) -> str:
        """
        Get regex pattern for finding function definition.
        
        Args:
            function_name: Function name to search
            language: Programming language
            
        Returns:
            Regex pattern string
        """
        if language == "python":
            return rf"def\s+{re.escape(function_name)}\s*\("
        elif language in ("javascript", "typescript"):
            patterns = [
                rf"function\s+{re.escape(function_name)}\s*\(",
                rf"const\s+{re.escape(function_name)}\s*=",
                rf"{re.escape(function_name)}\s*:\s*function",
                rf"{re.escape(function_name)}\s*=\s*\(",
            ]
            return "|".join(f"({p})" for p in patterns)
        elif language == "go":
            return rf"func\s+{re.escape(function_name)}\s*\("
        elif language == "java":
            return rf"\b{re.escape(function_name)}\s*\("
        else:
            # Generic pattern for unknown languages
            return re.escape(function_name)
    
    def get_class_pattern(self, class_name: str, language: LanguageType) -> str:
        """
        Get regex pattern for finding class definition.
        
        Args:
            class_name: Class name to search
            language: Programming language
            
        Returns:
            Regex pattern string
        """
        if language == "python":
            return rf"class\s+{re.escape(class_name)}\s*[:\(]"
        elif language in ("javascript", "typescript"):
            patterns = [
                rf"class\s+{re.escape(class_name)}\s*{{",
                rf"class\s+{re.escape(class_name)}\s+extends",
                rf"interface\s+{re.escape(class_name)}\s*{{",
            ]
            return "|".join(f"({p})" for p in patterns)
        elif language == "go":
            return rf"type\s+{re.escape(class_name)}\s+struct"
        elif language == "java":
            patterns = [
                rf"class\s+{re.escape(class_name)}\s*{{",
                rf"interface\s+{re.escape(class_name)}\s*{{",
            ]
            return "|".join(f"({p})" for p in patterns)
        else:
            return re.escape(class_name)
    
    def get_import_pattern(self, module_name: str, language: LanguageType) -> str:
        """
        Get regex pattern for finding imports.
        
        Args:
            module_name: Module/package name
            language: Programming language
            
        Returns:
            Regex pattern string
        """
        if language == "python":
            patterns = [
                rf"import\s+{re.escape(module_name)}",
                rf"from\s+{re.escape(module_name)}\s+import",
            ]
            return "|".join(f"({p})" for p in patterns)
        elif language in ("javascript", "typescript"):
            patterns = [
                rf"import\s+.*from\s+['\"].*{re.escape(module_name)}",
                rf"require\s*\(\s*['\"].*{re.escape(module_name)}",
            ]
            return "|".join(f"({p})" for p in patterns)
        elif language == "go":
            return rf"import\s+.*{re.escape(module_name)}"
        elif language == "java":
            return rf"import\s+.*{re.escape(module_name)}"
        else:
            return re.escape(module_name)
    
    def get_variable_pattern(self, var_name: str, language: LanguageType) -> str:
        """
        Get regex pattern for finding variable declarations.
        
        Args:
            var_name: Variable name
            language: Programming language
            
        Returns:
            Regex pattern string
        """
        if language == "python":
            return rf"\b{re.escape(var_name)}\s*="
        elif language in ("javascript", "typescript"):
            patterns = [
                rf"var\s+{re.escape(var_name)}\s*=",
                rf"let\s+{re.escape(var_name)}\s*=",
                rf"const\s+{re.escape(var_name)}\s*=",
            ]
            return "|".join(f"({p})" for p in patterns)
        elif language == "go":
            patterns = [
                rf"var\s+{re.escape(var_name)}\s+",
                rf"{re.escape(var_name)}\s*:=",
            ]
            return "|".join(f"({p})" for p in patterns)
        elif language == "java":
            return rf"\b\w+\s+{re.escape(var_name)}\s*="
        else:
            return rf"\b{re.escape(var_name)}\b"
    
    def extract_function_signature(
        self,
        lines: List[str],
        start_line: int,
        language: LanguageType
    ) -> Optional[str]:
        """
        Extract function signature from code.
        
        Args:
            lines: Code lines
            start_line: Line number where function starts (1-indexed)
            language: Programming language
            
        Returns:
            Function signature or None if not found
        """
        if start_line < 1 or start_line > len(lines):
            return None
        
        idx = start_line - 1
        line = lines[idx].strip()
        
        if language == "python":
            if "def " in line:
                # May span multiple lines
                sig = line
                idx += 1
                while idx < len(lines) and ":" not in sig:
                    sig += " " + lines[idx].strip()
                    idx += 1
                return sig.split(":")[0].strip()
        
        elif language in ("javascript", "typescript"):
            if any(kw in line for kw in ["function", "const", "let", "=>"]):
                sig = line
                idx += 1
                while idx < len(lines) and "{" not in sig:
                    sig += " " + lines[idx].strip()
                    idx += 1
                return sig.split("{")[0].strip()
        
        elif language == "go":
            if "func " in line:
                sig = line
                idx += 1
                while idx < len(lines) and "{" not in sig:
                    sig += " " + lines[idx].strip()
                    idx += 1
                return sig.split("{")[0].strip()
        
        elif language == "java":
            # Look back for annotations and modifiers
            sig_lines = []
            for i in range(max(0, idx - 3), idx + 1):
                sig_lines.append(lines[i].strip())
            sig = " ".join(sig_lines)
            if "{" in sig:
                sig = sig.split("{")[0].strip()
            return sig
        
        return line
    
    def get_comment_patterns(self, language: LanguageType) -> Dict[str, str]:
        """
        Get comment patterns for the language.
        
        Args:
            language: Programming language
            
        Returns:
            Dict with 'line' and 'block_start'/'block_end' patterns
        """
        if language == "python":
            return {
                "line": "#",
                "block_start": '"""',
                "block_end": '"""',
            }
        elif language in ("javascript", "typescript", "go", "java"):
            return {
                "line": "//",
                "block_start": "/*",
                "block_end": "*/",
            }
        else:
            return {"line": "#", "block_start": "", "block_end": ""}


# Singleton instance
_strategy = GrepStrategy()


def get_grep_strategy() -> GrepStrategy:
    """Get the global grep strategy instance."""
    return _strategy
