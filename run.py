#!/usr/bin/env python3
"""Top-level entry point.

Usage:
    python run.py samples/phishing.eml
    python run.py samples/bec_gmail.eml --mode agent
    python run.py samples/clean.eml --no-sandbox

This tiny shim exists so the project can be launched without pip-installing
the `sentinel` package. It just hands off to sentinel.main:main().
"""
import sys

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from sentinel.main import main

if __name__ == "__main__":
    sys.exit(main())
