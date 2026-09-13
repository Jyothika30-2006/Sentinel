"""Forensic report writer.

After an investigation completes, this module writes a full human-readable
transcript (Markdown + plain text) to reports/, including the risk timeline,
tool observations, verdict, and blockchain ledger reference. Nothing here
touches the network or the evidence bytes.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .config import CONFIG


def _fmt(d: Any) -> str:
    return json.dumps(d, indent=2, ensure_ascii=False, default=str)


def write_report(
    email_path: str,
    verdict: str,
    confidence: int,
    evidence: List[str],
    risk_events: List[Any],
    observations: List[str],
    ledger_ref: Dict[str, Any],
) -> str:
    """Write the forensic report and return its path."""
    CONFIG.ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = Path(email_path).stem.replace(" ", "_")
    path = Path(CONFIG.reports_dir) / f"report_{stem}_{ts}.md"

    lines = []
    lines.append(f"# Sentinel Forensic Report\n")
    lines.append(f"- **Case file:** `{email_path}`")
    lines.append(f"- **Generated:** {datetime.now().isoformat()}")
    lines.append(f"- **Final verdict:** {verdict} ({confidence}% confidence)")
    lines.append("")

    lines.append("## Evidence")
    for e in evidence:
        lines.append(f"- {e}")
    lines.append("")

    lines.append("## Risk score timeline")
    for ev in risk_events:
        lines.append(f"- `[{ev.ts}]` {ev.delta:+d} -> {ev.score}/100 — {ev.reason}")
    lines.append("")

    lines.append("## Tool observations")
    for o in observations:
        lines.append(f"- {o}")
    lines.append("")

    lines.append("## Blockchain ledger reference")
    lines.append("```json")
    lines.append(_fmt(ledger_ref))
    lines.append("```")

    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)
