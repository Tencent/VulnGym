# -*- coding: utf-8 -*-
"""包入口：允许 `python -m vulngym_verify_demo` 调用 CLI。"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())