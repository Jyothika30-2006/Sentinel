#!/usr/bin/env python3
"""Sentinel Guard — Interactive AI Cybersecurity Desktop Companion.

A floating, interactive desktop assistant that MIRRORS the Sentinel agent's live state,
provides desktop notifications, renders active threat animations, opens the web dashboard,
and allows right-click investigation controls.

Features:
  1. EXPRESSIONS & ANIMATIONS — face/aura changes by state & risk:
     idle (calm/breathing) -> scanning/investigating -> thinking (dots bubble) ->
     tool_running (focused shield) -> verdict (green happy hop / amber warning / red alarm shake).
  2. INTERACTIONS —
     - Left Click: Open Localhost Web Dashboard (http://127.0.0.1:5000).
     - Double Click: Open latest investigation forensic report.
     - Drag: Smoothly move the mascot anywhere on screen.
     - Right Click: Rich context menu (New EML Scan, Sample Cases, Reports, Ledger Verification, Settings, Hide/Exit).
  3. NOTIFICATIONS — Native OS desktop notifications on verdict discovery, threat detection, and ledger commits.
  4. SETTINGS — Custom dialog for Always-On-Top, Companion Scale, OS Toasts, and Auto Server Launch.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Dict, Optional, Tuple

# Bootstrap repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

if sys.platform == "win32":
    try:
        import ctypes
        user32 = ctypes.windll.user32
        hDesk = user32.OpenInputDesktop(0, False, 0x01FF) or user32.OpenDesktopW("default", 0, False, 0x01FF)
        if hDesk:
            user32.SetThreadDesktop(hDesk)
    except Exception:
        pass

from PySide6.QtCore import QPoint, QPointF, QRectF, Qt, QTimer, Signal, QObject
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPen, QCursor, QAction, QIcon, QPolygonF
from PySide6.QtWidgets import (QApplication, QLabel, QLineEdit, QListWidget,
                               QPushButton, QTextEdit, QVBoxLayout, QWidget,
                               QMenu, QFileDialog, QDialog, QCheckBox, QComboBox,
                               QFormLayout, QDialogButtonBox, QSystemTrayIcon, QStyle)

try:
    from . import sprites
except ImportError:
    import sprites

from sentinel.llm import make_client
from sentinel import statebus
from sentinel.blockchain import hashchain
from sentinel.config import CONFIG
from sentinel.email_activation import activation_manager
import sentinel.mail as mailmod
import sentinel.analyze as analyze_mod

_SCALE = 6
_PALETTE = sprites.PALETTE
_BODY = sprites.BODY
_SHIELD = sprites.SHIELD
_BANG = sprites.BANG
_DOTS = sprites.DOTS
_CHECK = sprites.CHECK
_ZZZ = sprites.ZZZ
_QMARK = sprites.QMARK
_STAR = sprites.STAR
_HEART = sprites.HEART
_SCAN_BAR = sprites.SCAN_BAR
_THINK_DOTS = sprites.THINK_DOTS


def _draw_grid(grid, scale, color_map) -> QImage:
    h, w = len(grid), len(grid[0])
    img = QImage(w * scale, h * scale, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    for y, row in enumerate(grid):
        for x, ch in enumerate(row):
            color = color_map.get(ch)
            if color is None:
                continue
            if isinstance(color, str):
                hx = color.lstrip("#")
                rgba = QColor(int(hx[0:2], 16), int(hx[2:4], 16), int(hx[4:6], 16), 255)
            else:
                rgba = color
            p.fillRect(x * scale, y * scale, scale, scale, rgba)
    p.end()
    return img


def notify(title: str, message: str) -> None:
    """Send OS desktop notification."""
    print(f"[Sentinel Guard Notify] {title}: {message}")
    if sys.platform == "win32":
        try:
            ps_script = f'[reflection.assembly]::loadwithpartialname("System.Windows.Forms"); [reflection.assembly]::loadwithpartialname("System.Drawing"); $notify = new-object system.windows.forms.notifyicon; $notify.icon = [system.drawing.systemicons]::information; $notify.visible = $true; $notify.showballoontip(3000, "{title}", "{message}", [system.windows.forms.tooltipicon]::info)'
            subprocess.Popen(["powershell", "-Command", ps_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            subprocess.run(["osascript", "-e", f'display notification "{message}" with title "{title}"'], timeout=3)
            return
        except Exception:
            pass


def find_gmail_window_geometry() -> Optional[Tuple[int, int, int, int]]:
    import shutil
    if not shutil.which("xdotool"):
        return None
    try:
        out = subprocess.run(["xdotool", "search", "--name", "Gmail"], capture_output=True, text=True, timeout=3).stdout.strip()
        if not out:
            return None
        wid = out.splitlines()[0]
        geo = subprocess.run(["xdotool", "getwindowgeometry", "--shell", wid], capture_output=True, text=True, timeout=3).stdout
        d = {}
        for line in geo.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
        if all(k in d for k in ("X", "Y", "WIDTH", "HEIGHT")):
            return int(d["X"]), int(d["Y"]), int(d["WIDTH"]), int(d["HEIGHT"])
    except Exception:
        return None
    return None


class StateReader(QObject):
    updated = Signal(dict)

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path
        self._last = {}
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        self.timer.start(200)

    def _poll(self):
        try:
            data = json.loads(Path(self.path).read_text(encoding="utf-8"))
        except Exception:
            return
        if data != self._last:
            self._last = data
            self.updated.emit(data)


# ---------------------------------------------------------------------------
# Settings Dialog
# ---------------------------------------------------------------------------
class SentinelSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sentinel Guard Settings")
        self.resize(340, 240)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.chk_always_on_top = QCheckBox("Keep Companion Always-on-Top")
        self.chk_always_on_top.setChecked(True)

        self.chk_notifications = QCheckBox("Enable Desktop Notifications")
        self.chk_notifications.setChecked(True)

        self.chk_watch = QCheckBox("Watch Mail Opens (Tier 3 — activate on open)")
        self.chk_watch.setChecked(True)
        self.chk_watch.setToolTip(
            "Sentinel activates ONLY when you open a mail. Watches the foreground\n"
            "browser tab title for a Gmail thread open (no account access — surface\n"
            "analysis, confidence capped). Install extension/ for full forensics."
        )

        self.chk_arrival = QCheckBox("Arrival Watch (auto-triage incoming mail)")
        self.chk_arrival.setToolTip(
            "Opt-in: every INCOMING Mailpit message is analyzed automatically\n"
            "(deterministic triage — no LLM quota). Requires a guard restart\n"
            "after toggling. Gmail arrivals: use the browser extension instead."
        )

        self.cmb_scale = QComboBox()
        self.cmb_scale.addItems(["Compact (0.8x)", "Normal (1.0x)", "Large (1.25x)", "Huge (1.5x)"])
        self.cmb_scale.setCurrentIndex(1)

        form.addRow("Windowing:", self.chk_always_on_top)
        form.addRow("Notifications:", self.chk_notifications)
        form.addRow("Activation:", self.chk_watch)
        form.addRow("Arrival Watch:", self.chk_arrival)
        form.addRow("Companion Size:", self.cmb_scale)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


# ---------------------------------------------------------------------------
# Sentinel Pet / Companion Main Widget
# ---------------------------------------------------------------------------
class SentinelPet(QWidget):
    def __init__(self, state_path: Optional[str] = None, draggable: bool = True,
                 static_pos: Optional[Tuple[int, int]] = None):
        super().__init__()
        self.risk = 0
        self.state = "idle"
        self._machine_state = "IDLE"
        self._is_reacting = False
        self._reaction_timer: Optional[QTimer] = None
        self.verdict: Optional[str] = None
        self.current_tool = ""
        self._t = 0.0
        self._draggable = draggable
        self._dragging = False
        self._drag_start_pos = QPoint()
        self._drag_offset = QPoint()
        self._wobble = 0.0
        self.talking = False
        self.chat_open = False
        self.chat_history: list = []
        self.bubble: Optional[str] = "Sentinel ready."
        self._last_notified_verdict = None

        self.setWindowTitle("Sentinel Guard")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(240, 300)

        # Tooltip for mouse hover
        self.setToolTip("Sentinel Guard — AI Security Assistant (Click to open Dashboard)")

        # System Tray Icon setup
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.tray.setToolTip("Sentinel Guard AI Cybersecurity Agent")
        self.tray.show()

        # Chat Input Box
        self.chat_input = QLineEdit(self)
        self.chat_input.setPlaceholderText("Ask Sentinel… (Enter to send)")
        self.chat_input.setGeometry(10, 270, 220, 24)
        self.chat_input.returnPressed.connect(self._send_chat)
        self.chat_input.hide()

        try:
            self.chat_client = make_client()
        except ValueError:
            from sentinel.llm import OllamaClient
            self.chat_client = OllamaClient()

        # State bus listener
        sp = state_path or str(statebus.state_file())
        self.reader = StateReader(sp)
        self.reader.updated.connect(self._on_state)

        # Animation timer (starts on demand, stopped when IDLE)
        self.anim = QTimer(self)
        self.anim.timeout.connect(self._tick)

        # Settings persistence defaults
        self.notifications_enabled = True
        self.always_on_top = True
        self.scale_index = 1
        self.title_watch_enabled = True
        self.arrival_watch_enabled = False

        # Positioning
        if static_pos:
            self.move(*static_pos)
        else:
            screen = QApplication.primaryScreen().availableGeometry()
            self.move(screen.right() - self.width() - 50, screen.center().y() - self.height() // 2)

        self.load_settings()

    def settings_file_path(self) -> Path:
        return _REPO_ROOT / "sentinel_settings.json"

    def load_settings(self):
        spath = self.settings_file_path()
        if spath.exists():
            try:
                import json
                with open(spath, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                pos = cfg.get("pos")
                if pos and isinstance(pos, list) and len(pos) == 2:
                    self.move(pos[0], pos[1])
                self.notifications_enabled = cfg.get("notifications", True)
                self.always_on_top = cfg.get("always_on_top", True)
                self.scale_index = cfg.get("scale_index", 1)
                self.title_watch_enabled = cfg.get("title_watch_enabled", True)
                self.arrival_watch_enabled = cfg.get("arrival_watch_enabled", False)
            except Exception as e:
                print(f"[SentinelPet] Failed to load settings: {e}")

    def save_settings(self):
        try:
            import json
            # Merge with the existing file so non-pet keys (watcher settings)
            # written by sentinel/watcher.py survive.
            cfg = {}
            spath = self.settings_file_path()
            if spath.exists():
                try:
                    cfg = json.loads(spath.read_text(encoding="utf-8"))
                except Exception:
                    cfg = {}
            cfg.update({
                "pos": [self.x(), self.y()],
                "notifications": self.notifications_enabled,
                "always_on_top": self.always_on_top,
                "scale_index": self.scale_index,
                "title_watch_enabled": getattr(self, "title_watch_enabled", True),
                "arrival_watch_enabled": getattr(self, "arrival_watch_enabled", False),
            })
            with open(spath, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception as e:
            print(f"[SentinelPet] Failed to save settings: {e}")

    def apply_settings(self):
        """Apply the current settings to the live widget (window flags, etc.)."""
        flags = Qt.FramelessWindowHint | Qt.Tool
        if self.always_on_top:
            flags |= Qt.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        self.show()  # re-create the native window after flag change

    # ── Centralized State Machine Controller ─────────────────────────────────────
    def set_state(self, new_state: str, extra_data: dict | None = None) -> None:
        """Centralized State Machine Controller for Sentinel Guard.

        States: LOCKED, IDLE, SCANNING, THINKING, THREAT_DETECTED,
                SAFE, SUSPICIOUS, MALICIOUS, COMPLETE, ERROR
        """
        data = extra_data or {}
        st = new_state.upper()

        if st in ("INVESTIGATING", "TOOL_RUNNING"):
            st = "SCANNING"
        elif st == "CONFIRM_NEEDED":
            st = "THREAT_DETECTED"
        elif st == "VERDICT":
            st = (data.get("verdict") or "IDLE").upper()

        if hasattr(self, "_machine_state") and self._machine_state == st and not data.get("force"):
            if "message" in data and data["message"]:
                self.bubble = data["message"]
            self.update()
            return

        self._machine_state = st
        self.state = st.lower()
        if "risk" in data and data["risk"] is not None:
            self.risk = int(data.get("risk", 0))
        if "verdict" in data and data["verdict"] is not None:
            self.verdict = data.get("verdict")
        if "message" in data and data["message"]:
            self.bubble = data["message"]

        # 1. Clean up prior reaction timers
        if hasattr(self, "_reaction_timer") and self._reaction_timer:
            try:
                self._reaction_timer.stop()
                self._reaction_timer.deleteLater()
            except Exception:
                pass
            self._reaction_timer = None

        self._is_reacting = False
        self._wobble = 0.0

        # 2. State-Driven Animations
        if st in ("SCANNING", "THINKING"):
            # Active processing state: start frame timer for cyan scan beam
            self._start_anim_timer()
        elif st in ("SAFE", "SUSPICIOUS", "MALICIOUS", "THREAT_DETECTED"):
            # Finite event reaction: play 1.8s animation then settle into stable IDLE
            self._is_reacting = True
            if st in ("SUSPICIOUS", "MALICIOUS", "THREAT_DETECTED"):
                self._wobble = 1.0
            self._start_anim_timer()

            self._reaction_timer = QTimer(self)
            self._reaction_timer.setSingleShot(True)
            self._reaction_timer.timeout.connect(self._on_reaction_finished)
            self._reaction_timer.start(1800)
        elif st == "LOCKED":
            self.bubble = "Sentinel Locked"
            self._stop_anim_timer()
            self.update()
        else:
            # IDLE / COMPLETE / ERROR: 100% STABLE, NO SHAKING, ZERO TIMER CPU!
            self._machine_state = "IDLE"
            self.state = "idle"
            self._stop_anim_timer()
            self.update()

    def _on_reaction_finished(self):
        """Finite reaction timeout finished -> settle into STABLE IDLE state!"""
        self._is_reacting = False
        self._wobble = 0.0
        if hasattr(self, "_reaction_timer") and self._reaction_timer:
            try:
                self._reaction_timer.stop()
                self._reaction_timer.deleteLater()
            except Exception:
                pass
            self._reaction_timer = None
        self._machine_state = "IDLE"
        self.state = "idle"
        self._stop_anim_timer()
        self.update()

    def _start_anim_timer(self):
        if hasattr(self, "anim") and not self.anim.isActive():
            self.anim.start(33)

    def _stop_anim_timer(self):
        if hasattr(self, "anim") and self.anim.isActive():
            self.anim.stop()

    def _on_state(self, data: dict):
        raw_state = data.get("state", "idle")
        verdict = data.get("verdict")
        risk = int(data.get("risk", 0))

        if raw_state == "verdict" and verdict:
            target_state = verdict
        elif raw_state in ("investigating", "tool_running"):
            target_state = "SCANNING"
        elif raw_state == "thinking":
            target_state = "THINKING"
        elif raw_state == "confirm_needed":
            target_state = "THREAT_DETECTED"
        elif raw_state == "idle":
            target_state = "IDLE"
        else:
            target_state = raw_state.upper()

        self.set_state(target_state, extra_data=data)

        # Trigger OS desktop notification on new verdict
        if verdict and verdict != self._last_notified_verdict:
            self._last_notified_verdict = verdict
            msg = data.get("message", "")
            notify(f"Sentinel Verdict: {verdict}", f"Risk Score: {risk}/100 — {msg}")


    def show_notification(self, title: str, msg: str):
        self.tray.showMessage(title, msg, QSystemTrayIcon.Information, 4000)
        notify(title, msg)

    def open_dashboard(self):
        webbrowser.open("http://127.0.0.1:5000")

    def toggle_chat(self):
        self.chat_open = not self.chat_open
        self.chat_input.setVisible(self.chat_open)
        if self.chat_open:
            self.chat_input.setFocus()
            self.bubble = "Hi! Ask me about emails or threats."
        self.update()

    def _send_chat(self):
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()
        self.chat_history.append({"role": "user", "content": text})
        self.talking = True
        self.bubble = text
        self.update()
        
        def work():
            try:
                resp = self.chat_client.chat(
                    messages=[{"role": "system", "content": "You are Sentinel Guard, an AI cybersecurity expert assistant. Answer briefly (1-2 sentences)."}] + self.chat_history[-6:]
                )
                reply_text = self.chat_client.extract_text(resp).strip() or "Sentinel active. All systems safe."
            except Exception:
                reply_text = "I'm keeping watch over your email threats locally."
            
            from PySide6.QtCore import QMetaObject, Q_ARG
            QMetaObject.invokeMethod(self, "_on_reply", Qt.QueuedConnection, Q_ARG(str, reply_text))

        threading.Thread(target=work, daemon=True).start()

    def _on_reply(self, text: str):
        self.chat_history.append({"role": "assistant", "content": text})
        self.talking = False
        self.bubble = text
        self.update()

    # Context Menu
    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #0F172A; color: #FFF; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 6px; } QMenu::item:selected { background-color: #1E293B; }")

        act_scan = menu.addAction("🔍 Investigate EML File...")
        act_dashboard = menu.addAction("🌐 Open Web Dashboard")
        menu.addSeparator()

        sample_menu = menu.addMenu("🧪 Run Sample Case")
        act_s1 = sample_menu.addAction("Clean Email (clean.eml)")
        act_s2 = sample_menu.addAction("Phishing Attempt (phishing.eml)")
        act_s3 = sample_menu.addAction("BEC Webmail (bec_gmail.eml)")
        act_s4 = sample_menu.addAction("Malware PDF (malware_attachment.eml)")

        menu.addSeparator()
        act_ledger = menu.addAction("🔗 Verify Blockchain Ledger")
        act_watch = None
        if sys.platform == "win32":
            act_watch = menu.addAction(
                f"👁️ Watch Mail Opens: {'ON' if self.title_watch_enabled else 'OFF'}")
        act_arrival = menu.addAction(
            f"📥 Arrival Watch: {'ON' if getattr(self, 'arrival_watch_enabled', False) else 'OFF'}")
        act_settings = menu.addAction("⚙️ Sentinel Guard Settings...")
        act_logout = menu.addAction("🔒 Lock / Logout Agent")
        menu.addSeparator()
        act_hide = menu.addAction("👁️ Hide Companion")
        act_exit = menu.addAction("❌ Exit Sentinel Guard")

        action = menu.exec(event.globalPos())

        if action == act_scan:
            self._select_and_scan_eml()
        elif action == act_dashboard:
            self.open_dashboard()
        elif action == act_s1:
            self._run_sample("clean.eml")
        elif action == act_s2:
            self._run_sample("phishing.eml")
        elif action == act_s3:
            self._run_sample("bec_gmail.eml")
        elif action == act_s4:
            self._run_sample("malware_attachment.eml")
        elif action == act_ledger:
            self._verify_ledger()
        elif act_watch is not None and action == act_watch:
            self.title_watch_enabled = not self.title_watch_enabled
            self.save_settings()
            state = "ON" if self.title_watch_enabled else "OFF"
            self.show_notification("Sentinel Guard", f"Watch Mail Opens toggled {state}.")
        elif action == act_arrival:
            self.arrival_watch_enabled = not getattr(self, "arrival_watch_enabled", False)
            self.save_settings()
            state = "ON" if self.arrival_watch_enabled else "OFF"
            note = (" Requires a Sentinel Guard restart to start/stop polling." if state == "ON" else "")
            self.show_notification("Sentinel Guard", f"Arrival Watch toggled {state}.{note}")
        elif action == act_settings:
            dlg = SentinelSettingsDialog(self)
            dlg.chk_always_on_top.setChecked(self.always_on_top)
            dlg.chk_notifications.setChecked(self.notifications_enabled)
            dlg.chk_watch.setChecked(getattr(self, "title_watch_enabled", True))
            dlg.chk_arrival.setChecked(getattr(self, "arrival_watch_enabled", False))
            dlg.cmb_scale.setCurrentIndex(self.scale_index)
            if dlg.exec() == QDialog.Accepted:
                self.always_on_top = dlg.chk_always_on_top.isChecked()
                self.notifications_enabled = dlg.chk_notifications.isChecked()
                self.title_watch_enabled = dlg.chk_watch.isChecked()
                self.arrival_watch_enabled = dlg.chk_arrival.isChecked()
                self.scale_index = dlg.cmb_scale.currentIndex()
                self.save_settings()
                self.apply_settings()
        elif action == act_logout:
            activation_manager.revoke_session()
            self.show_notification("Sentinel Guard", "Session revoked. Agent is now LOCKED.")
            QApplication.quit()
        elif action == act_hide:
            self.hide()
            self.show_notification("Sentinel Guard", "Companion minimized. Click system tray icon to restore.")
        elif action == act_exit:
            QApplication.quit()

    def _select_and_scan_eml(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select EML File for Investigation", "", "Email Files (*.eml)")
        if file_path:
            self._start_investigation_thread(file_path)

    def _run_sample(self, sample_name: str):
        sample_path = str(_REPO_ROOT / "samples" / sample_name)
        if os.path.exists(sample_path):
            self._start_investigation_thread(sample_path)
        else:
            self.show_notification("Error", f"Sample file {sample_name} not found.")

    def _start_investigation_thread(self, email_path: str):
        self.state = "investigating"
        self.bubble = f"Investigating {Path(email_path).name}..."
        self.show_notification("Sentinel Guard", f"Starting forensic analysis on {Path(email_path).name}")
        self.update()

        def work():
            from app import run_sentinel_investigation
            try:
                res = run_sentinel_investigation(email_path, use_llm=False)
                verdict = res.get("verdict", "UNKNOWN")
                risk = res.get("risk_score", 0)
                conf = res.get("confidence", 0)
                self.show_notification(f"Verdict: {verdict}", f"Confidence: {conf}% | Risk: {risk}/100")
            except Exception as exc:
                self.show_notification("Error", f"Analysis error: {exc}")

        threading.Thread(target=work, daemon=True).start()

    def _verify_ledger(self):
        chain = hashchain.HashChain()
        res = chain.verify()
        if res["valid"]:
            self.show_notification("Ledger Verified", f"Cryptographic Hash Chain intact! ({res['length']} blocks verified)")
        else:
            self.show_notification("Ledger Warning", f"Tampering detected at block #{res['broken_at']}!")

    # Mouse Handlers
    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_start_pos = e.globalPosition().toPoint()
            self._dragging = True
            self._drag_offset = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._dragging and self._draggable:
            self.move(e.globalPosition().toPoint() - self._drag_offset)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton:
            dist = (e.globalPosition().toPoint() - self._drag_start_pos).manhattanLength()
            self._dragging = False
            self.save_settings()
            if dist < 6:
                # Simple Left Click -> Open Dashboard!
                self.open_dashboard()

    def mouseDoubleClickEvent(self, e):
        if e.button() == Qt.LeftButton:
            # Double click -> open recent report
            reports_dir = CONFIG.reports_dir
            if os.path.exists(reports_dir):
                reports = sorted(Path(reports_dir).glob("*.md"), key=os.path.getmtime, reverse=True)
                if reports:
                    webbrowser.open(str(reports[0]))
                    return
            self.open_dashboard()

    def _expression(self) -> str:
        if self.talking:
            return "talking"
        if getattr(self, "_is_reacting", False):
            if self.verdict == "SAFE":
                return "happy"
            if self.verdict == "MALICIOUS" or self.risk >= 80:
                return "alarmed"
            return "alert"
        if self.state in ("thinking", "investigating", "scanning"):
            return "thinking"
        if self.state == "confirm_needed":
            return "alert"
        if self.risk >= 80:
            return "alarmed"
        if self.risk >= 60:
            return "frown"
        if self.risk >= 35:
            return "neutral"
        return "idle"

    def _body_char(self) -> str:
        if self.verdict == "SAFE":
            return "g"
        if self.risk < 35:
            return "g"
        if self.risk < 60:
            return "y"
        if self.risk < 80:
            return "o"
        return "r"

    def _tick(self):
        self._t += 0.03
        if self._wobble > 0:
            self._wobble = max(0.0, self._wobble - 0.05)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.SmoothPixmapTransform, False)
        p.setRenderHint(QPainter.Antialiasing, True)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2 - 15

        expr = self._expression()

        # Wobble / shake ONLY during active event-driven reaction (settles to 0 when idle)
        wob = 0.0
        if getattr(self, "_is_reacting", False) and self._wobble > 0:
            wob = math.sin(self._t * 30) * 3 * self._wobble

        # Hop / bob ONLY during active safe event reaction
        bob = 0.0
        if getattr(self, "_is_reacting", False) and self.verdict == "SAFE":
            bob = -abs(math.sin(self._t * 5)) * 6


        # ── Glow aura behind card (risk-coloured) ──────────────────────────
        aura_alpha = int(30 + 20 * math.sin(self._t * 3))
        if self.risk >= 80:
            aura_col = QColor(231, 76, 60, aura_alpha)       # red
        elif self.risk >= 50:
            aura_col = QColor(241, 196, 15, aura_alpha)      # amber
        elif expr in ("happy", "idle") and self.state == "verdict":
            aura_col = QColor(46, 204, 113, aura_alpha)      # green
        else:
            aura_col = QColor(52, 152, 219, aura_alpha)      # blue
        p.setPen(Qt.NoPen)
        p.setBrush(aura_col)
        p.drawEllipse(QPointF(cx + wob, cy + bob), 68, 58)

        cmap = dict(_PALETTE)
        body_char = self._body_char()
        cmap["g"] = cmap["y"] = cmap["o"] = cmap["r"] = _PALETTE[body_char]

        # ── Soft Risk Aura behind mascot (no card box!) ────────────────────
        aura_alpha = int(35 + 25 * math.sin(self._t * 3))
        if self.risk >= 80:
            aura_col = QColor(239, 68, 68, aura_alpha)       # red
        elif self.risk >= 50:
            aura_col = QColor(245, 158, 11, aura_alpha)      # amber
        elif expr in ("happy", "idle") and self.state == "verdict":
            aura_col = QColor(16, 185, 129, aura_alpha)      # green
        else:
            aura_col = QColor(59, 130, 246, aura_alpha)      # blue
        p.setPen(Qt.NoPen)
        p.setBrush(aura_col)
        p.drawEllipse(QPointF(cx + wob, cy + bob), 62, 52)

        # ── Body sprite ─────────────────────────────────────────────────────
        body = _draw_grid(_BODY, _SCALE, cmap)
        bw, bh = body.width(), body.height()
        bx, by = cx - bw / 2 + wob, cy - bh / 2 + bob

        # ── Ground Drop Shadow under feet ──────────────────────────────────
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(0, 0, 0, 75))
        p.drawEllipse(QPointF(cx + wob, by + bh - 2), 38, 9)

        # Draw Mascot Image
        p.drawImage(int(bx), int(by), body)

        # ── Scanning beam (cyan sweep) ──────────────────────────────────────
        if self.state in ("investigating", "tool_running", "thinking"):
            scan_x = bx + ((math.sin(self._t * 4) + 1) / 2) * bw
            scan_alpha = int(180 + 60 * math.sin(self._t * 8))
            scan_col = QColor(6, 182, 212, scan_alpha)
            p.setPen(QPen(scan_col, 2))
            p.drawLine(int(scan_x), int(by - 2), int(scan_x), int(by + bh + 2))

        # ── Eye animation (follow cursor) ───────────────────────────────────
        g = QCursor.pos()
        center = self.frameGeometry().center()
        dx, dy = g.x() - center.x(), g.y() - center.y()
        mag = math.hypot(dx, dy) or 1.0
        ex, ey = (dx / mag) * 3.5, (dy / mag) * 2.5

        # Blink every ~4s
        blink = (self._t % 4.0) < 0.12
        pupil_col = QColor("#1a1a2e")
        white_col = QColor("#ffffff")
        eye_y = by + bh * 0.38
        eye_r = 5
        gap = 18

        for sx in (-1, 1):
            ecx = cx + sx * gap / 2 + wob
            if blink:
                p.setBrush(QColor(255, 255, 255, 60))
                p.setPen(Qt.NoPen)
                p.drawEllipse(QPointF(ecx, eye_y), eye_r, 1.5)
            else:
                p.setBrush(white_col)
                p.setPen(Qt.NoPen)
                p.drawEllipse(QPointF(ecx, eye_y), eye_r, eye_r)
                p.setBrush(pupil_col)
                p.drawEllipse(QPointF(ecx + ex * 0.4, eye_y + ey * 0.4), 2.5, 2.5)

        # ── Expression glyph bubble ─────────────────────────────────────────
        glyph, color = None, "#ffffff"
        if expr == "thinking":
            glyph, color = _DOTS, "#a29bfe"
        elif expr == "alert":
            glyph, color = _BANG, "#f1c40f"
        elif expr == "happy":
            glyph, color = _HEART, "#2ecc71"
        elif expr == "alarmed":
            glyph, color = _BANG, "#e74c3c"
        if glyph:
            g_img = _draw_grid(glyph, 6, {".": None, "k": color})
            p.drawImage(int(bx + bw + 2), int(by - 22), g_img)

        # ── Floating Speech Bubble ──────────────────────────────────────────
        if self.bubble:
            self._draw_speech_bubble(p, cx, by - 12, self.bubble)

        # ── Floating Status Pill Badge (bottom) ─────────────────────────────
        self._draw_status_pill(p, cx, by + bh + 14)


    def _draw_speech_bubble(self, p, cx, top_y, text):
        p.setFont(QFont("Inter", 8))
        metrics = p.fontMetrics()
        words = text.split()
        lines, cur = [], ""
        for wrd in words:
            trial = (cur + " " + wrd).strip()
            if metrics.horizontalAdvance(trial) > 170:
                lines.append(cur)
                cur = wrd
            else:
                cur = trial
        if cur:
            lines.append(cur)
        tw = max((metrics.horizontalAdvance(l) for l in lines), default=0) + 16
        th = len(lines) * (metrics.height() + 2) + 8
        x = cx - tw / 2
        y = top_y - th - 8

        # Comic speech bubble rectangle
        p.setPen(QPen(QColor("rgba(59, 130, 246, 0.4)"), 1.2))
        p.setBrush(QColor(15, 23, 42, 235))
        p.drawRoundedRect(QRectF(x, y, tw, th), 10, 10)

        # Pointer tail
        pointer = QPolygonF([
            QPointF(cx - 5, y + th),
            QPointF(cx + 5, y + th),
            QPointF(cx, y + th + 6)
        ])
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(15, 23, 42, 235))
        p.drawPolygon(pointer)

        # Text inside bubble
        p.setPen(QPen(QColor("#F8FAFC")))
        for i, l in enumerate(lines):
            p.drawText(QRectF(x + 8, y + 4 + i * (metrics.height() + 2), tw - 16, metrics.height()), Qt.AlignCenter, l)

    def _draw_status_pill(self, p, cx, y):
        lbl = self._status_label()
        p.setFont(QFont("Inter", 8, QFont.Bold))
        metrics = p.fontMetrics()
        tw = metrics.horizontalAdvance(lbl) + 26
        th = 22
        x = cx - tw / 2

        # Status dot color
        if self.risk >= 80:
            dot_col = QColor("#EF4444")
        elif self.risk >= 50:
            dot_col = QColor("#F59E0B")
        elif self.state == "verdict" and self.verdict == "SAFE":
            dot_col = QColor("#10B981")
        else:
            dot_col = QColor("#3B82F6")

        # Glass pill backdrop
        p.setPen(QPen(QColor(dot_col.red(), dot_col.green(), dot_col.blue(), 100), 1))
        p.setBrush(QColor(15, 23, 42, 220))
        p.drawRoundedRect(QRectF(x, y, tw, th), 11, 11)

        # Glowing status dot
        p.setPen(Qt.NoPen)
        p.setBrush(dot_col)
        p.drawEllipse(QPointF(x + 12, y + th / 2), 3.5, 3.5)

        # Pill text
        p.setPen(QPen(QColor("#F8FAFC")))
        p.drawText(QRectF(x + 20, y + 2, tw - 24, th - 2), Qt.AlignLeft | Qt.AlignVCenter, lbl)

    def _status_label(self) -> str:
        if self.state == "investigating":
            return "INVESTIGATING…"
        if self.state == "tool_running":
            return f"RUN {self.current_tool or 'tool'}"
        if self.state == "verdict":
            return f"{self.verdict} ({self.risk}/100)"
        return f"SENTINEL — {self.risk}/100"


# ---------------------------------------------------------------------------
# Email Activation & Recovery Dialog — Gate before Pet companion
# ---------------------------------------------------------------------------
class ActivationDialog(QDialog):

    activated = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sentinel Guard — Email OTP Activation & Recovery")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(460, 520)

        self._mode = "request"  # request, verify_otp, recovery_request, recovery_verify
        self._email = ""
        self._cooldown_timer = None
        self._cooldown_seconds = 0

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.card = QFrame()
        self.card.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(15, 23, 42, 0.98), stop:1 rgba(8, 12, 20, 0.99));
                border: 1px solid rgba(59, 130, 246, 0.35);
                border-radius: 20px;
            }
        """)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(36, 28, 36, 28)
        card_layout.setSpacing(12)

        # Shield icon
        shield_label = QLabel("🛡️")
        shield_label.setAlignment(Qt.AlignCenter)
        shield_label.setStyleSheet("font-size: 48px; margin-bottom: 2px;")
        card_layout.addWidget(shield_label)

        # Title
        self.status_label = QLabel("Sentinel Agent → LOCKED")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            color: #EF4444;
            font-size: 18px;
            font-weight: 700;
            font-family: 'Inter', 'Segoe UI', sans-serif;
            letter-spacing: 1px;
        """)
        card_layout.addWidget(self.status_label)

        # Subtitle
        self.subtitle = QLabel("Activate your email ID to unlock Sentinel.")
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setWordWrap(True)
        self.subtitle.setStyleSheet("""
            color: #94A3B8;
            font-size: 12px;
            font-family: 'Inter', 'Segoe UI', sans-serif;
        """)
        card_layout.addWidget(self.subtitle)

        # Divider
        divider = QLabel()
        divider.setFixedHeight(1)
        divider.setStyleSheet("background: rgba(59, 130, 246, 0.2); margin: 4px 0;")
        card_layout.addWidget(divider)

        # Input 1: Email
        self.email_label = QLabel("Email ID")
        self.email_label.setStyleSheet("color: #CBD5E1; font-size: 12px; font-weight: 600; font-family: 'Inter', sans-serif;")
        card_layout.addWidget(self.email_label)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("your@email.com")
        self.email_input.setStyleSheet("""
            QLineEdit {
                background: rgba(30, 41, 59, 0.9);
                border: 1px solid rgba(59, 130, 246, 0.3);
                border-radius: 10px;
                padding: 10px 14px;
                color: #F8FAFC;
                font-size: 14px;
                font-family: 'JetBrains Mono', 'Consolas', monospace;
            }
            QLineEdit:focus { border-color: #3B82F6; }
        """)
        card_layout.addWidget(self.email_input)

        # Input 2: 6-digit OTP Code (hidden initially)
        self.otp_label = QLabel("6-Digit Verification Code")
        self.otp_label.setStyleSheet("color: #CBD5E1; font-size: 12px; font-weight: 600; font-family: 'Inter', sans-serif;")
        self.otp_label.hide()
        card_layout.addWidget(self.otp_label)

        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("123456")
        self.otp_input.setMaxLength(6)
        self.otp_input.setAlignment(Qt.AlignCenter)
        self.otp_input.setStyleSheet("""
            QLineEdit {
                background: rgba(30, 41, 59, 0.9);
                border: 1px solid rgba(59, 130, 246, 0.4);
                border-radius: 10px;
                padding: 10px 14px;
                color: #06B6D4;
                font-size: 18px;
                font-weight: 700;
                letter-spacing: 6px;
                font-family: 'JetBrains Mono', monospace;
            }
            QLineEdit:focus { border-color: #06B6D4; }
        """)
        self.otp_input.hide()
        card_layout.addWidget(self.otp_input)

        # Main Action Button
        self.main_btn = QPushButton("📧  Activate Email")
        self.main_btn.setCursor(Qt.PointingHandCursor)
        self.main_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3B82F6, stop:1 #2563EB);
                color: white; border: none; border-radius: 10px; padding: 11px;
                font-size: 14px; font-weight: 600; font-family: 'Inter', sans-serif;
            }
            QPushButton:hover { background: #2563EB; }
            QPushButton:disabled { background: #334155; color: #64748B; }
        """)
        self.main_btn.clicked.connect(self._on_main_btn_clicked)
        card_layout.addWidget(self.main_btn)

        # Secondary Button (Resend OTP / Back)
        self.sec_btn = QPushButton("🔁 Resend Code")
        self.sec_btn.setCursor(Qt.PointingHandCursor)
        self.sec_btn.setStyleSheet("""
            QPushButton {
                background: transparent; color: #94A3B8; border: 1px solid rgba(255,255,255,0.1);
                border-radius: 8px; padding: 6px 12px; font-size: 12px; font-family: 'Inter', sans-serif;
            }
            QPushButton:hover { color: #FFF; border-color: rgba(255,255,255,0.25); }
        """)
        self.sec_btn.hide()
        self.sec_btn.clicked.connect(self._on_resend_clicked)
        card_layout.addWidget(self.sec_btn)

        # Feedback text
        self.feedback = QLabel("")
        self.feedback.setAlignment(Qt.AlignCenter)
        self.feedback.setWordWrap(True)
        self.feedback.setStyleSheet("color: #94A3B8; font-size: 12px; font-family: 'Inter', sans-serif;")
        card_layout.addWidget(self.feedback)

        # Recovery link
        self.recovery_btn = QPushButton("🔑 Lost Session? Recover Access")
        self.recovery_btn.setCursor(Qt.PointingHandCursor)
        self.recovery_btn.setStyleSheet("background: none; border: none; color: #60A5FA; font-size: 11px; text-decoration: underline; font-family: 'Inter', sans-serif;")
        self.recovery_btn.clicked.connect(self._toggle_recovery_mode)
        card_layout.addWidget(self.recovery_btn)

        layout.addWidget(self.card)

    def _on_main_btn_clicked(self):
        if self._mode == "request":
            email = self.email_input.text().strip()
            if not email or "@" not in email:
                self._show_error("Please enter a valid email address.")
                return
            try:
                activation_manager.request_activation(email)
                self._email = email
                self._switch_to_verify_mode("activation")
            except ValueError as exc:
                self._show_error(str(exc))

        elif self._mode == "verify_otp":
            code = self.otp_input.text().strip()
            if len(code) != 6:
                self._show_error("Please enter the 6-digit verification code.")
                return
            try:
                token = activation_manager.verify_activation(self._email, code)
                self._on_activation_success(token)
            except ValueError as exc:
                self._show_error(str(exc))

        elif self._mode == "recovery_request":
            email = self.email_input.text().strip()
            if not email or "@" not in email:
                self._show_error("Please enter your previously verified email address.")
                return
            try:
                activation_manager.request_recovery(email)
                self._email = email
                self._switch_to_verify_mode("recovery")
            except ValueError as exc:
                self._show_error(str(exc))

        elif self._mode == "recovery_verify":
            code = self.otp_input.text().strip()
            if len(code) != 6:
                self._show_error("Please enter the 6-digit recovery code.")
                return
            try:
                token = activation_manager.verify_recovery(self._email, code)
                self._on_activation_success(token)
            except ValueError as exc:
                self._show_error(str(exc))

    def _switch_to_verify_mode(self, vtype: str):
        if vtype == "recovery":
            self._mode = "recovery_verify"
            self.status_label.setText("Account Recovery")
            self.subtitle.setText(f"Enter the 6-digit recovery code sent to {self._email}")
            self.main_btn.setText("🔓 Verify & Recover Session")
        else:
            self._mode = "verify_otp"
            self.status_label.setText("Enter Verification Code")
            self.subtitle.setText(f"A 6-digit OTP code was sent to {self._email}")
            self.main_btn.setText("✓ Verify & Activate")

        self.email_input.setEnabled(False)
        self.otp_label.show()
        self.otp_input.show()
        self.otp_input.setFocus()
        self.sec_btn.show()
        self.feedback.setStyleSheet("color: #10B981; font-size: 12px; font-family: 'Inter', sans-serif;")
        self.feedback.setText("OTP code dispatched to your email. (Code expires in 10 mins)")
        self._start_cooldown_timer(60)

    def _on_resend_clicked(self):
        try:
            activation_manager.resend_code(self._email)
            self.feedback.setStyleSheet("color: #10B981; font-size: 12px; font-family: 'Inter', sans-serif;")
            self.feedback.setText("Fresh 6-digit code sent to your email.")
            self._start_cooldown_timer(60)
        except ValueError as exc:
            self._show_error(str(exc))

    def _start_cooldown_timer(self, seconds: int):
        self._cooldown_seconds = seconds
        self.sec_btn.setEnabled(False)
        self.sec_btn.setText(f"Resend Code ({self._cooldown_seconds}s)")

        if self._cooldown_timer:
            self._cooldown_timer.stop()

        self._cooldown_timer = QTimer(self)
        self._cooldown_timer.timeout.connect(self._tick_cooldown)
        self._cooldown_timer.start(1000)

    def _tick_cooldown(self):
        self._cooldown_seconds -= 1
        if self._cooldown_seconds <= 0:
            self._cooldown_timer.stop()
            self.sec_btn.setEnabled(True)
            self.sec_btn.setText("🔁 Resend Code")
        else:
            self.sec_btn.setText(f"Resend Code ({self._cooldown_seconds}s)")

    def _toggle_recovery_mode(self):
        if self._mode in ("request", "verify_otp"):
            self._mode = "recovery_request"
            self.status_label.setText("Account Recovery")
            self.subtitle.setText("Enter your previously verified email address to recover session.")
            self.email_input.setEnabled(True)
            self.email_input.clear()
            self.otp_label.hide()
            self.otp_input.hide()
            self.main_btn.setText("📩 Send Recovery Code")
            self.recovery_btn.setText("← Back to Activation")
            self.feedback.setText("")
        else:
            self._mode = "request"
            self.status_label.setText("Sentinel Agent → LOCKED")
            self.subtitle.setText("Activate your email ID to unlock Sentinel.")
            self.email_input.setEnabled(True)
            self.email_input.clear()
            self.otp_label.hide()
            self.otp_input.hide()
            self.main_btn.setText("📧  Activate Email")
            self.recovery_btn.setText("🔑 Lost Session? Recover Access")
            self.feedback.setText("")

    def _on_activation_success(self, token: str):
        self.status_label.setText("Email Verified ✓")
        self.status_label.setStyleSheet("color: #10B981; font-size: 18px; font-weight: 700; letter-spacing: 1px;")
        self.subtitle.setText("Sentinel Agent → ACTIVE")
        self.subtitle.setStyleSheet("color: #3B82F6; font-size: 14px; font-weight: 600;")
        self.main_btn.hide()
        self.sec_btn.hide()
        self.otp_input.setEnabled(False)
        self.feedback.setStyleSheet("color: #10B981; font-size: 13px; font-weight: 600;")
        self.feedback.setText("Session Authenticated! Opening Sentinel Guard companion...")
        QTimer.singleShot(1000, self._finish)

    def _show_error(self, msg: str):
        self.feedback.setStyleSheet("color: #EF4444; font-size: 12px; font-family: 'Inter', sans-serif;")
        self.feedback.setText(msg)

    def _finish(self):
        self.activated.emit()
        self.accept()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag_pos)


def main_guard() -> int:
    app = QApplication(sys.argv)

    print("\n  🛡️ Sentinel Agent → ACTIVE\n")

    pet = SentinelPet(draggable=True)
    pet.show()
    pet.raise_()
    pet.activateWindow()

    pet.show_notification("Sentinel Guard Active", "Sentinel Guard desktop companion is running. Click mascot to open Dashboard.")
    return app.exec()


def main() -> int:
    return main_guard()


if __name__ == "__main__":
    sys.exit(main())
