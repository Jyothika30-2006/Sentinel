#!/usr/bin/env python3
"""forensic_tool.py — runs INSIDE the sandbox against one attachment.

Usage:  python3 /overlay/forensic_tool.py <tool> <file>

Runs exactly ONE whitelisted forensic binary against the file and prints a
JSON result to stdout. The tool name must match a fixed entry in TOOLS below
— there is NO shell, NO free-form command, and the file path is passed as a
single argv element (safe against path/argument injection).

This is the sandbox-side counterpart of static_scan.py: it extends the pet /
agent from "metadata/entropy/macros" into full Parrot/REMNux-style analysis:

    binwalk   : detect embedded/concatenated files (file carving signatures)
    pdfid     : PDF exploit/anomaly detection (JS, OpenAction, Launch, ...)
    capa      : Mandiant FLARE capability detection (what malware CAN do)
    strings   : ASCII string extraction + suspicious-string scanning
    yara      : signature matching against a rules directory
    pecheck   : PE (Windows executable) structural analysis

Each tool degrades gracefully: if its binary is missing from the image it
returns {"available": false} rather than crashing, so a partial image build
never breaks an investigation.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

# Rules directory is mounted alongside this script (see Dockerfile + sandbox.py).
_RULES_DIR = "/overlay/yara_rules"


# ---------------------------------------------------------------------------
# Generic runner
# ---------------------------------------------------------------------------
def _run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": True, "stdout": p.stdout, "stderr": p.stderr, "rc": p.returncode}
    except FileNotFoundError:
        return {"ok": False, "error": f"binary not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timed out"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def _require(tool, exe):
    if not shutil.which(exe):
        return None
    return tool


# ---------------------------------------------------------------------------
# Individual tools
# ---------------------------------------------------------------------------
def tool_binwalk(path):
    if not shutil.which("binwalk"):
        return {"available": False, "tool": "binwalk", "note": "binwalk not installed"}
    r = _run(["binwalk", "--signature", "--quiet", path])
    lines = [l for l in r["stdout"].splitlines() if l.strip()]
    # Detect embedded-file signature lines (e.g. "1234  0x4D2   Zip archive data").
    embedded = []
    for l in lines:
        if re.search(r"\b(Zip archive|PDF document|PE32|ELF|JPEG|PNG|gzip|7-zip|Executable|Microsoft Office)", l):
            embedded.append(l)
    return {
        "available": True, "tool": "binwalk",
        "signatures_found": len(lines),
        "embedded_files": embedded,
        "flags": [f"binwalk: embedded file at {l.split()[0]}" for l in embedded[:10]],
    }


def tool_pdfid(path):
    if not shutil.which("pdfid"):
        return {"available": False, "tool": "pdfid", "note": "pdfid not installed"}
    r = _run(["pdfid", path])
    suspicious = []
    # pdfid prints "  /JS  1" style lines; suspicious = count > 0.
    for l in r["stdout"].splitlines():
        m = re.match(r"\s*(/\w+)\s+(\d+)", l)
        if m and m.group(1) in ("/JS", "/JavaScript", "/OpenAction", "/Launch",
                                "/EmbeddedFile", "/AA", "/JBIG2Decode", "/RichMedia",
                                "/AcroForm", "/XFA") and int(m.group(2)) > 0:
            suspicious.append(f"{m.group(1)}={m.group(2)}")
    return {
        "available": True, "tool": "pdfid",
        "suspicious_keywords": suspicious,
        "flags": [f"pdfid: {s} present" for s in suspicious],
    }


def tool_capa(path):
    if not shutil.which("capa"):
        return {"available": False, "tool": "capa", "note": "capa not installed"}
    r = _run(["capa", "-j", "-q", path])
    techniques = []
    try:
        data = json.loads(r["stdout"] or "{}")
        # Capa JSON: {"rules": {...}, "meta": {...}}. Rules carry att&ck ids.
        for rule_id, rule in (data.get("rules") or {}).items():
            for t in rule.get("meta", {}).get("attack", []):
                techniques.append({"rule": rule_id, "technique": t})
    except Exception:
        pass
    return {
        "available": True, "tool": "capa",
        "techniques": techniques,
        "flags": [f"capa: {t['rule']} -> {t['technique']}" for t in techniques[:10]],
    }


def tool_strings(path):
    if not shutil.which("strings"):
        return {"available": False, "tool": "strings", "note": "strings not installed"}
    r = _run(["strings", "-n", "6", path])
    lines = r["stdout"].splitlines()
    suspicious = []
    for l in lines:
        if re.search(r"https?://|(?:\d{1,3}\.){3}\d{1,3}", l):
            suspicious.append(l)
        elif re.search(r"\b(cmd\.exe|powershell|/bin/sh|bash -|wget |curl |nc -|base64 -d)\b", l, re.I):
            suspicious.append(l)
    return {
        "available": True, "tool": "strings",
        "total_strings": len(lines),
        "suspicious": suspicious[:20],
        "flags": [f"strings: suspicious '{s[:50]}'" for s in suspicious[:10]],
    }


def tool_yara(path):
    if not shutil.which("yara"):
        return {"available": False, "tool": "yara", "note": "yara not installed"}
    if not os.path.isdir(_RULES_DIR):
        return {"available": False, "tool": "yara", "note": "no rules directory"}
    rules = [f for f in os.listdir(_RULES_DIR) if f.endswith((".yar", ".yara"))]
    if not rules:
        return {"available": True, "tool": "yara", "matches": [], "note": "no rules loaded"}
    matches = []
    for rule_file in rules:
        r = _run(["yara", "-w", os.path.join(_RULES_DIR, rule_file), path])
        for l in r["stdout"].splitlines():
            if l.strip():
                matches.append(l.strip())
    return {
        "available": True, "tool": "yara",
        "rules_scanned": rules,
        "matches": matches,
        "flags": [f"yara: {m}" for m in matches],
    }


def tool_pecheck(path):
    if not shutil.which("pecheck"):
        return {"available": False, "tool": "pecheck", "note": "pecheck not installed"}
    r = _run(["pecheck", "-l", "1", path])
    anomalies = [l for l in r["stdout"].splitlines() if "SUSPICIOUS" in l.upper() or "! " in l]
    return {
        "available": True, "tool": "pecheck",
        "anomalies": anomalies,
        "flags": [f"pecheck: {a}" for a in anomalies[:10]],
    }


TOOLS = {
    "binwalk": tool_binwalk,
    "pdfid": tool_pdfid,
    "capa": tool_capa,
    "strings": tool_strings,
    "yara": tool_yara,
    "pecheck": tool_pecheck,
}


def main() -> int:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: forensic_tool.py <tool> <file>"}))
        return 2
    tool_name, path = sys.argv[1], sys.argv[2]
    if tool_name not in TOOLS:
        print(json.dumps({"error": f"tool '{tool_name}' not in whitelist"}))
        return 2
    if not os.path.isfile(path):
        print(json.dumps({"error": f"file not found: {path}"}))
        return 2
    result = TOOLS[tool_name](path)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
