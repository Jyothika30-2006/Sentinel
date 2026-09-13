"""Running risk score tracker (0-100).

The score is updated after EVERY tool observation. Each update carries a
human-readable `reason` so the terminal transcript is a full chain-of-
reasoning audit trail, not just a number.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List

# Severity thresholds for color-coding.
SEVERITY = {
    "LOW": (0, 34),
    "MODERATE": (35, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}


@dataclass
class RiskEvent:
    """A single recorded change to the risk score."""
    ts: str
    delta: int
    score: int
    reason: str


def severity_for(score: int) -> str:
    """Map a 0-100 score to a severity label."""
    for label, (lo, hi) in SEVERITY.items():
        if lo <= score <= hi:
            return label
    return "CRITICAL" if score > 100 else "LOW"


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


class RiskTracker:
    """Clamped 0-100 accumulator with a full event log."""

    def __init__(self) -> None:
        self.score: int = 0
        self.events: List[RiskEvent] = []

    def update(self, delta: int, reason: str) -> int:
        """Apply `delta` (clamped to 0..100) and record the change."""
        self.score = max(0, min(100, self.score + delta))
        self.events.append(RiskEvent(_stamp(), delta, self.score, reason))
        self._publish_mascot_hook()
        return self.score

    def _publish_mascot_hook(self) -> None:
        """Publish the live risk score for the desktop pet (statebus + legacy file).

        This is a soft hook: failures are ignored and never affect analysis.
        The statebus file drives overlay/sentinel_pet.py; the legacy JSON file
        is kept for backward compatibility with the simpler overlay demo.
        """
        try:
            from . import statebus

            statebus.publish(risk=self.score, message=self.events[-1].reason)
        except Exception:
            pass
        try:
            path = os.environ.get("SENTINEL_RISK_FILE", "/tmp/sentinel_risk.json")
            Path(path).write_text(json.dumps({"risk": self.score}))
        except Exception:
            pass

    @property
    def severity(self) -> str:
        return severity_for(self.score)

    def summary_lines(self) -> List[str]:
        """Return the event log as compact lines for the report/UI."""
        lines = []
        for e in self.events:
            sign = "+" if e.delta >= 0 else ""
            lines.append(f"[{e.ts}] {sign}{e.delta} -> {e.score}/100 : {e.reason}")
        return lines
