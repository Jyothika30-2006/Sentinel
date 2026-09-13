"""Headless analysis — run the Sentinel pipeline without a terminal.

Lets the desktop pet (or any GUI) invoke a full investigation on a raw email
and get back a structured dict (verdict, confidence, risk, evidence) instead
of parsing terminal output. Reuses the exact same Agent + tools, just with a
silent UI and auto-confirmation of sandbox steps.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict

from .agent import Agent
from .config import CONFIG
from .killswitch import KILLSWITCH
from .ui import TerminalUI


class SilentUI:
    """A UI with the same interface as TerminalUI but no terminal output.

    Used so Agent.run() works headlessly (from the desktop pet). All methods
    are no-ops; risk is still tracked inside the Agent's RiskTracker.
    """

    def __init__(self) -> None:
        self.history = []
        self.risk = {"score": 0, "reason": ""}

    def start(self, email_path: str) -> None:
        pass

    def stop(self) -> None:
        pass

    def banner(self, email_path: str) -> None:
        pass

    def set_risk(self, score: int, reason: str) -> None:
        self.risk = {"score": score, "reason": reason}

    def log(self, message: str, style: str = "") -> None:
        pass

    def reason(self, text: str) -> None:
        pass

    def tool(self, name: str, args: dict) -> None:
        pass

    def observation(self, summary: str) -> None:
        pass

    def verdict(self, verdict: str, confidence: int) -> None:
        pass


def analyze_raw(raw_email: str, use_llm: bool = False) -> Dict:
    """Write raw email to a temp .eml, run the agent, return the result dict.

    `use_llm=False` (default) runs the deterministic pipeline — instant and
    offline. Set True to use Ollama if it's available.
    """
    # newline="" keeps the mail's own \r\n endings intact (text-mode default
    # would turn them into \r\r\n on Windows and truncate the parsed headers).
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False,
                                     newline="") as fh:
        fh.write(raw_email)
        path = fh.name

    try:
        return analyze_file(path, use_llm=use_llm)
    finally:
        try:
            Path(path).unlink(missing_ok=True)
        except Exception:
            pass


def analyze_file(email_path: str, use_llm: bool = False) -> Dict:
    """Run the agent on an .eml path and return {verdict, confidence, ...}.

    Safety notes preserved: hashing-before-analysis, tool whitelist, sandbox
    for static_file_scan, and timeouts all still apply. Confirmation is
    auto-approved ONLY because this path is triggered by an explicit GUI
    action (the user clicked 'Analyze').
    """
    KILLSWITCH.reset()
    agent = Agent(SilentUI(), email_path, use_llm=use_llm, auto_confirm=True)
    result = agent.run()
    return {
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "risk_score": result["risk_score"],
        "evidence": result.get("evidence", []),
        "geolocation_summary": result.get("geolocation_summary", "n/a"),
    }


# Re-export TerminalUI so callers importing analyze can choose either.
__all__ = ["analyze_raw", "analyze_file", "SilentUI"]
