"""Docker sandbox isolation layer.

Any file-touching operation (currently `static_file_scan`) runs inside a
one-shot Docker container built from sandbox/Dockerfile, with:

  * READ-ONLY mount of the evidence directory (container cannot modify it),
  * NO default network (--network none) — only the static analysis tools run,
  * hard CPU/time limits and `--rm` so the container is destroyed after use,
  * a `cap-drop ALL` / non-root user to minimize blast radius.

If Docker is unavailable OR sandbox is disabled, static_file_scan falls back
to host-side tooling but clearly flags `sandboxed: False` and still NEVER
executes the file (metadata/entropy/type analysis only).

Design note: the spec also mentions REMnux. The same static-analysis script
(overlay/static_scan.py) runs on REMnux directly — swap the Docker backend
for a REMnux VM by pointing the tools at it; the contract (JSON in/out) is
identical, so the agent code does not change.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .config import CONFIG

_IMAGE = "sentinel-sandbox:latest"
_HOST_TOOLS = {
    "exiftool": "exiftool",
    "oleid": "oleid",
    "file": "file",
}


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        return False


def _host_tools_available() -> list[str]:
    return [t for t, exe in _HOST_TOOLS.items() if shutil.which(exe)]


def run_static_scan(attachment_path: str) -> dict:
    """Run the static analysis script against one attachment.

    Returns a dict with `sandboxed` (bool) and `results` (dict) plus any
    `error`. Never executes the target file.
    """
    attachment_path = os.path.abspath(attachment_path)
    src = Path(attachment_path)
    if not src.is_file():
        raise FileNotFoundError(f"attachment not found: {attachment_path}")

    # Only the evidence dir + the overlay script are exposed to the sandbox.
    evidence_dir = str(src.parent)
    overlay_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "overlay"))

    use_docker = CONFIG.sandbox_enabled and _docker_available()

    if use_docker:
        return _run_in_docker(attachment_path, evidence_dir, overlay_dir)
    return _run_on_host(attachment_path)


def _run_in_docker(attachment_path: str, evidence_dir: str, overlay_dir: str) -> dict:
    """One-shot, network-less, read-only container."""
    rel = Path(attachment_path).name
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",                # NO network egress
        "--cap-drop", "ALL",                # drop all Linux capabilities
        "--memory", "512m",                 # memory cap
        "--pids-limit", "64",               # fork-bomb guard
        "--cpus", "1",
        "--user", "65534:65534",            # nobody
        "--read-only",                      # read-only rootfs
        "-v", f"{overlay_dir}:/overlay:ro",     # static_scan.py (read-only)
        "-v", f"{evidence_dir}:/evidence:ro",   # evidence (READ-ONLY mount)
        "-w", "/tmp",
        _IMAGE,
        "python3", "/overlay/static_scan.py", f"/evidence/{rel}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CONFIG.tool_timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"sandboxed": True, "error": f"analysis timed out after {CONFIG.tool_timeout_seconds}s"}
    except FileNotFoundError:
        return {"sandboxed": True, "error": "docker not found"}

    if proc.returncode != 0:
        return {"sandboxed": True, "error": proc.stderr.strip() or f"exit {proc.returncode}"}

    try:
        results = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        results = {"raw_stdout": proc.stdout.strip()}
    return {"sandboxed": True, "results": results}


def _run_on_host(attachment_path: str) -> dict:
    """Fallback: run overlay/static_scan.py on the host (still never executes file)."""
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "overlay", "static_scan.py"))
    cmd = [ "python3", script, attachment_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CONFIG.tool_timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"sandboxed": False, "error": f"analysis timed out after {CONFIG.tool_timeout_seconds}s"}
    try:
        results = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        results = {"raw_stdout": proc.stdout.strip()}
    return {"sandboxed": False, "results": results, "warning": "Docker unavailable — ran on host (static-only, no execution)"}


# ---------------------------------------------------------------------------
# Forensic binaries (binwalk / pdfid / capa / strings / yara / pecheck)
# ---------------------------------------------------------------------------
_FORENSIC_TOOLS = {"binwalk", "pdfid", "capa", "strings", "yara", "pecheck"}


def run_forensic_tool(tool: str, attachment_path: str) -> dict:
    """Run ONE whitelisted forensic binary against an attachment in the sandbox.

    `tool` MUST be in _FORENSIC_TOOLS (validated here, and again inside the
    sandbox script). Returns the parsed JSON result from overlay/forensic_tool.py.
    """
    if tool not in _FORENSIC_TOOLS:
        return {"error": f"forensic tool '{tool}' not in whitelist"}
    attachment_path = os.path.abspath(attachment_path)
    src = Path(attachment_path)
    if not src.is_file():
        raise FileNotFoundError(f"attachment not found: {attachment_path}")

    evidence_dir = str(src.parent)
    overlay_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "overlay"))
    rel = src.name

    use_docker = CONFIG.sandbox_enabled and _docker_available()

    if use_docker:
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--cap-drop", "ALL",
            "--memory", "512m",
            "--pids-limit", "64",
            "--cpus", "1",
            "--user", "65534:65534",
            "--read-only",
            "-v", f"{overlay_dir}:/overlay:ro",
            "-v", f"{evidence_dir}:/evidence:ro",
            "-w", "/tmp",
            _IMAGE,
            "python3", "/overlay/forensic_tool.py", tool, f"/evidence/{rel}",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=CONFIG.tool_timeout_seconds)
        except subprocess.TimeoutExpired:
            return {"sandboxed": True, "error": "timed out"}
        if proc.returncode != 0:
            return {"sandboxed": True, "error": proc.stderr.strip() or f"exit {proc.returncode}"}
        try:
            return {"sandboxed": True, "tool": tool, "results": json.loads(proc.stdout.strip() or "{}")}
        except json.JSONDecodeError:
            return {"sandboxed": True, "tool": tool, "results": {"raw": proc.stdout.strip()}}

    # Host fallback: run the same dispatcher directly (binaries likely absent,
    # but strings is commonly present and safe — it only reads bytes).
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "overlay", "forensic_tool.py"))
    cmd = ["python3", script, tool, attachment_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CONFIG.tool_timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"sandboxed": False, "error": "timed out"}
    try:
        results = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        results = {"raw": proc.stdout.strip()}
    return {"sandboxed": False, "tool": tool, "results": results,
            "warning": "Docker unavailable — ran on host (static-only, no execution)"}
