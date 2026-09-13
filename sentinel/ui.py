"""Terminal UI built on `rich` — live-updating, colored, no web server.

Two rendering modes:
  * interactive (real TTY): a `rich.Live` dashboard with a color-coded risk
    gauge, streaming reasoning, and a scrolling log.
  * non-interactive (piped/CI/captured): a clean scrollable transcript —
    each log line is printed as it happens, with the same colors. This keeps
    the demo readable when output is redirected, and avoids Live's cursor
    control codes flooding a captured log.

No Flask, no React, no browser — exactly as the spec requires.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, List

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from .risk import severity_for

SEVERITY_COLORS = {
    "LOW": "green",
    "MODERATE": "yellow",
    "HIGH": "orange1",
    "CRITICAL": "red",
}

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

_IS_TTY = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
# Force terminal mode so colors + panels render even when output is piped
# (e.g. captured demo transcripts). `width` avoids 80-col wrapping surprises.
_console = Console(force_terminal=True, color_system="standard", width=120, legacy_windows=False if sys.platform == "win32" else None)


def color_for(score: int) -> str:
    return SEVERITY_COLORS[severity_for(score)]


class TerminalUI:
    """Live dashboard (TTY) or plain transcript (piped)."""

    def __init__(self) -> None:
        self.console = _console
        self.interactive = _IS_TTY
        self.history: List[str] = []
        self.risk: Dict[str, Any] = {"score": 0, "reason": "initialized"}
        self._live: Live | None = None

    # --- lifecycle ---------------------------------------------------
    def start(self, email_path: str) -> None:
        if self.interactive:
            self._live = Live(self._render(), console=self.console, refresh_per_second=8)
            self._live.start()
        self.banner(email_path)

    def stop(self) -> None:
        if self._live:
            self._live.stop()

    def banner(self, email_path: str) -> None:
        self.console.print(
            Panel.fit(
                f"[bold cyan]SENTINEL[/] — AI Email Threat & Forensics Agent\n"
                f"Investigating: [bold]{email_path}[/]\n"
                f"[dim]Kill-switch: press [bold]q / x / ESC[/] to abort instantly. "
                f"Ctrl+C also works.[/dim]",
                border_style="cyan",
            )
        )

    # --- live-updating primitives ------------------------------------
    def _render(self):
        score = self.risk["score"]
        c = color_for(score)
        gauge = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        task = gauge.add_task(f"[{c}]RISK", total=100)
        gauge.update(task, completed=score)

        hist = Text()
        for line in self.history[-24:]:
            hist.append(Text.from_markup(line + "\n"))

        return Group(
            Panel(gauge, title="[bold]Risk Score[/]", border_style=c),
            Panel(hist, title="[bold]Investigation Log[/]", border_style="white", height=18),
        )

    def _emit(self, message: str) -> None:
        """Print a line: to the Live panel (TTY) or straight to stdout (pipe)."""
        if self.interactive:
            self.history.append(message)
            self._refresh()
        else:
            self.console.print(message)

    def set_risk(self, score: int, reason: str) -> None:
        self.risk = {"score": score, "reason": reason}
        if self.interactive:
            self._refresh()

    def log(self, message: str, style: str = "") -> None:
        self._emit(message)

    def reason(self, text: str) -> None:
        """Stream a reasoning/thinking line from the agent."""
        self._emit(f"[bold magenta]thinking[/] [dim]»[/] {text}")

    def tool(self, name: str, args: dict) -> None:
        self._emit(f"[bold cyan]{name}[/][dim]({_short(args)})[/]")

    def observation(self, summary: str) -> None:
        self._emit(f"    [dim]→[/] {summary}")

    def verdict(self, verdict: str, confidence: int) -> None:
        c = "green" if verdict == "SAFE" else ("yellow" if verdict == "SUSPICIOUS" else "red")
        self._emit(f"[bold {c}]VERDICT: {verdict} ({confidence}% confidence)[/]")

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())


def _short(args: dict) -> str:
    """Compact, safe rendering of tool args (truncate long bodies).

    Long blob args (body/headers) are summarized by length, not content, so
    the log stays scannable and never floods the terminal with raw email.
    """
    if not args:
        return ""
    parts = []
    for k, v in args.items():
        s = str(v)
        if k in ("body", "headers") and len(s) > 80:
            s = f"<{k} len={len(s)}>"
        else:
            s = s.replace("\n", " ")
            if len(s) > 60:
                s = s[:57] + "..."
        parts.append(f"{k}={s}")
    return ", ".join(parts)


def render_verdict_panel(verdict: str, confidence: int, evidence: List[str], risk: int) -> None:
    """Print the final, non-live verdict panel."""
    c = "green" if verdict == "SAFE" else ("yellow" if verdict == "SUSPICIOUS" else "red")
    table = Table(title=f"[bold {c}]FINAL VERDICT: {verdict}[/]", border_style=c)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    table.add_row("Confidence", f"{confidence}%")
    table.add_row("Risk score", f"{risk}/100")
    ev = "\n".join(f"  • {e}" for e in evidence) if evidence else "  • (none)"
    table.add_row("Evidence", ev)
    _console.print(table)
