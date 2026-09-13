#!/usr/bin/env python3
"""Sentinel Desktop Mascot — a small animated "guard" that watches over Gmail.

WHAT IT IS
----------
A tiny, always-on-top, frameless, translucent desktop character that sits at
the corner of your Gmail browser window and reacts live to the agent's risk
score (calm -> alert -> alarm). It does NOT capture keystrokes, read screen
content, or touch the browser — it only:
  1. detects the Gmail window's geometry (via X11), and
  2. positions itself at that window's edge, and
  3. changes expression/animation based on the latest risk score.

REQUIREMENTS (optional — this is a bonus UI, not part of the agent core):
    pip install PySide6
    Linux + X11 (Windows/macOS use native Qt positioning without Gmail-snap).

RUN:
    python overlay/run_overlay.py                # demo animation
    python overlay/run_overlay.py --follow       # snap to Gmail window
    python overlay/run_overlay.py --risk-file /tmp/sentinel_risk.json
                                                 # react to live agent risk
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QPointF, QRectF, Signal, QObject
from PySide6.QtGui import QPainter, QColor, QFont, QBrush, QPen, QRadialGradient
from PySide6.QtWidgets import QApplication, QWidget


# ---------------------------------------------------------------------------
# Optional: Gmail window detection (Linux/X11 only). Returns x, y, w, h or None.
# ---------------------------------------------------------------------------
def find_gmail_window_geometry():
    """Locate a browser window whose title contains 'Gmail' via xdotool/xprop."""
    import shutil
    import subprocess

    if not shutil.which("xdotool"):
        return None
    try:
        # Search active window titles for "Gmail".
        out = subprocess.run(
            ["xdotool", "search", "--name", "Gmail"],
            capture_output=True, text=True, timeout=3,
        ).stdout.strip()
        if not out:
            return None
        wid = out.splitlines()[0]
        geo = subprocess.run(
            ["xdotool", "getwindowgeometry", "--shell", wid],
            capture_output=True, text=True, timeout=3,
        ).stdout
        d = {}
        for line in geo.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
        if "X" in d and "Y" in d and "WIDTH" in d and "HEIGHT" in d:
            return int(d["X"]), int(d["Y"]), int(d["WIDTH"]), int(d["HEIGHT"])
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Risk watcher: polls a JSON file the agent can write (optional live hook).
# ---------------------------------------------------------------------------
class RiskWatcher(QObject):
    updated = Signal(int)  # risk score 0-100

    def __init__(self, path: str | None) -> None:
        super().__init__()
        self.path = path
        self._last = -1
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        if self.path:
            self.timer.start(800)

    def _poll(self):
        try:
            data = json.loads(Path(self.path).read_text())
            score = int(data.get("risk", 0))
        except Exception:
            return
        if score != self._last:
            self._last = score
            self.updated.emit(score)


# ---------------------------------------------------------------------------
# The character widget: a simple round "sentinel" that pulses by risk level.
# ---------------------------------------------------------------------------
class Mascot(QWidget):
    def __init__(self, follow_gmail: bool = False, risk_watcher: RiskWatcher | None = None):
        super().__init__()
        self.risk = 0
        self._t = 0.0
        self._follow = follow_gmail

        # Frameless, always-on-top, translucent, click-through-capable.
        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(120, 120)

        # Animation timer.
        self.anim = QTimer(self)
        self.anim.timeout.connect(self._tick)
        self.anim.start(50)  # ~20 FPS

        if risk_watcher:
            risk_watcher.updated.connect(self.set_risk)

        if follow_gmail:
            self._snap_to_gmail()

    # --- risk --------------------------------------------------------
    def set_risk(self, score: int):
        self.risk = max(0, min(100, score))

    def _severity_color(self) -> QColor:
        if self.risk < 35:
            return QColor(46, 204, 113)      # green: calm
        if self.risk < 60:
            return QColor(241, 196, 15)      # yellow: alert
        if self.risk < 80:
            return QColor(230, 126, 34)      # orange: high
        return QColor(231, 76, 60)           # red: critical

    # --- positioning -------------------------------------------------
    def _snap_to_gmail(self):
        geo = find_gmail_window_geometry()
        if geo:
            x, y, w, h = geo
            # Place at the bottom-right corner of the Gmail window, just
            # overlapping its edge so it "covers" only that corner.
            self.move(x + w - 96, y + h - 96)

    # --- animation ---------------------------------------------------
    def _tick(self):
        self._t += 0.05
        if self._follow and self._t % 20 < 0.05:  # re-snap ~every second
            self._snap_to_gmail()
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2

        # Pulse amplitude scales with risk.
        pulse = 1.0 + 0.06 * math.sin(self._t * 4) * (0.5 + self.risk / 100)
        r = 44.0 * pulse

        # Glow.
        glow = QRadialGradient(QPointF(cx, cy), r * 1.8)
        c = self._severity_color()
        glow.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 120))
        glow.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 0))
        p.setBrush(QBrush(glow))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(cx, cy), r * 1.8, r * 1.8)

        # Body.
        p.setBrush(QBrush(c))
        p.setPen(QPen(QColor(255, 255, 255, 160), 2))
        p.drawEllipse(QPointF(cx, cy), r, r)

        # Eyes (blink) + mouth change with severity.
        p.setBrush(QBrush(QColor(255, 255, 255)))
        p.setPen(Qt.NoPen)
        blink = 1.0 if (self._t % 4) > 0.2 else 0.15
        eye_r = 7.0
        eye_dy = 12.0
        p.drawEllipse(QPointF(cx - 15, cy - eye_dy), eye_r, eye_r * blink)
        p.drawEllipse(QPointF(cx + 15, cy - eye_dy), eye_r, eye_r * blink)
        p.setBrush(QBrush(QColor(20, 20, 20)))
        p.drawEllipse(QPointF(cx - 15, cy - eye_dy), 3.5, 3.5 * blink)
        p.drawEllipse(QPointF(cx + 15, cy - eye_dy), 3.5, 3.5 * blink)

        # Mouth: smile -> flat -> frown -> open alarm.
        pen = QPen(QColor(255, 255, 255), 3)
        p.setPen(pen)
        if self.risk < 35:
            p.drawArc(QRectF(cx - 14, cy - 6, 28, 24), 0 * 16, 180 * 16)      # smile
        elif self.risk < 60:
            p.drawLine(int(cx - 12), int(cy + 8), int(cx + 12), int(cy + 8))  # neutral
        elif self.risk < 80:
            p.drawArc(QRectF(cx - 14, cy + 6, 28, 20), 180 * 16, 180 * 16)    # frown
        else:
            p.setBrush(QBrush(QColor(120, 0, 0)))
            p.drawEllipse(QPointF(cx, cy + 10), 10, 10)                        # alarm "O"

        # Label.
        p.setPen(QPen(QColor(255, 255, 255)))
        f = QFont("Sans", 9, QFont.Bold)
        p.setFont(f)
        p.drawText(QRectF(0, h - 22, w, 20), Qt.AlignCenter, f"RISK {self.risk}")
        p.end()


def main() -> int:
    ap = argparse.ArgumentParser(description="Sentinel desktop mascot")
    ap.add_argument("--follow", action="store_true", help="snap to the Gmail window (Linux/X11)")
    ap.add_argument("--risk-file", type=str, default=None,
                    help="JSON file to poll for {'risk': 0-100} live updates")
    args = ap.parse_args()

    app = QApplication(sys.argv)
    watcher = RiskWatcher(args.risk_file) if args.risk_file else None
    mascot = Mascot(follow_gmail=args.follow, risk_watcher=watcher)
    mascot.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
