#!/usr/bin/env python3
"""Sandbox-side dispatcher shim for static_scan.py (backward-compatible).

Kept minimal; the real forensic dispatch is overlay/forensic_tool.py.
"""
# This file intentionally left as a thin placeholder so the overlay package
# import graph stays flat. static_scan.py remains the entry for the
# metadata/entropy/macro path; forensic_tool.py is the entry for the
# binwalk/pdfid/capa/strings/yara/pecheck path.
