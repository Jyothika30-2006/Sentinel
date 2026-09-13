#!/usr/bin/env python3
"""static_scan.py — runs INSIDE the sandbox against one attachment.

Reads the file at argv[1], performs static-only analysis, prints a JSON
result to stdout. This script NEVER executes the target — it only computes
metadata, entropy, magic-type, and macro presence.

It is mounted read-only into the container at /overlay/static_scan.py and
invoked as:  python3 /overlay/static_scan.py /evidence/<file>
"""
import json
import math
import os
import sys
import tempfile
import zipfile
from collections import Counter


def sha256(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size(path: str) -> int:
    return os.path.getsize(path)


def entropy(path: str) -> float:
    """Shannon entropy of the file bytes. >7.0 is suspicious (packed/encrypted)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def magic_type(path: str) -> str:
    """File type by magic bytes (stdlib only; no external `file` needed)."""
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if head.startswith(b"%PDF"):
        return "PDF document"
    if head.startswith(b"MZ"):
        return "Windows PE executable"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP archive / OOXML (docx/xlsx)"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE2 compound file (legacy .doc/.xls)"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "GIF image"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head[:4] == b"RIFF":
        return "RIFF container (AVI/WAV/WEBP)"
    return "unknown/plain-text"


def ole_macro_scan(path: str) -> dict:
    """Detect macros in OLE2/OOXML without executing anything.

    For OLE2 (.doc/.xls): parse the directory stream for 'VBA'/'Macros'
    storage names. For OOXML (.docx/.xlsx): look for vbaProject.bin inside
    the zip. Both are pure-parse operations (no macro VM runs).
    """
    result = {"has_macros": False, "method": "none", "detail": ""}
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)

        if head.startswith(b"\xd0\xcf\x11\xe0"):
            # OLE2: scan raw bytes for the presence of 'VBA' / 'Macros' storage.
            with open(path, "rb") as fh:
                data = fh.read()
            if b"VBA" in data or b"Macros" in data or b"VBAProject" in data:
                result.update(has_macros=True, method="ole2-storage-scan", detail="VBA/Macro storage present")
            else:
                result.update(method="ole2-storage-scan", detail="no macro storage found")

        elif head.startswith(b"PK\x03\x04"):
            # OOXML: inspect zip member names for vbaProject.bin
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            if any("vbaProject.bin" in n for n in names):
                result.update(has_macros=True, method="ooxml-zip-member", detail="vbaProject.bin present")
            else:
                result.update(method="ooxml-zip-member", detail="no vbaProject.bin")
        else:
            result.update(method="none", detail="not an OLE/OOXML container")
    except Exception as exc:
        result.update(method="error", detail=str(exc))
    return result


def exiftool_metadata(path: str) -> dict:
    """Best-effort exiftool metadata (runs the external `exiftool` binary if
    present; otherwise falls back to basic filename/size/magic only)."""
    import shutil
    import subprocess

    if not shutil.which("exiftool"):
        return {"available": False, "note": "exiftool not installed in sandbox image"}
    try:
        proc = subprocess.run(
            ["exiftool", "-j", path],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode == 0:
            return {"available": True, "data": json.loads(proc.stdout.strip() or "[]")}
        return {"available": True, "error": proc.stderr.strip()}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def type_mismatch(path: str, magic: str) -> dict:
    """Compare extension vs. real magic type (e.g. .exe renamed .pdf)."""
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    suspicious = []
    is_exec = "executable" in magic  # covers "PE executable" and "ELF executable"
    # Any executable masquerading as a document/image extension is a mismatch.
    if is_exec and ext not in ("exe", "bin", "elf", "dll", "so", ""):
        suspicious.append(f"{magic} disguised as .{ext}")
    # Also: declared image ext but magic says something entirely different.
    if ext in ("jpg", "jpeg", "png", "gif") and "image" not in magic and magic != "unknown/plain-text":
        suspicious.append(f".{ext} is actually {magic}")
    return {
        "extension": ext,
        "detected_type": magic,
        "mismatch": bool(suspicious),
        "flags": suspicious,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "no file argument"}))
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(json.dumps({"error": f"file not found: {path}"}))
        sys.exit(1)

    magic = magic_type(path)
    ent = entropy(path)
    macros = ole_macro_scan(path)
    meta = exiftool_metadata(path)
    mismatch = type_mismatch(path, magic)

    result = {
        "sha256": sha256(path),
        "size_bytes": file_size(path),
        "entropy": round(ent, 4),
        "entropy_high": ent > 7.0,
        "magic_type": magic,
        "type_mismatch": mismatch,
        "macros": macros,
        "metadata": meta,
        "risk_flags": [],
    }

    if ent > 7.0:
        result["risk_flags"].append("high-entropy (packed/encrypted?)")
    if mismatch["mismatch"]:
        result["risk_flags"].extend(mismatch["flags"])
    if macros["has_macros"]:
        result["risk_flags"].append("contains VBA/macros")

    print(json.dumps(result))


if __name__ == "__main__":
    main()
