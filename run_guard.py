#!/usr/bin/env python3
"""SENTINEL GUARD — Unified Launcher.

Launches the interactive Sentinel Guard Desktop AI Assistant companion AND
ensures the local web dashboard server (http://127.0.0.1:5000) is active.

Usage:
    python run_guard.py
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.request
from pathlib import Path

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

# Ensure root is on sys.path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def is_server_running(url: str = "http://127.0.0.1:5000/api/status") -> bool:
    try:
        req = urllib.request.urlopen(url, timeout=1)
        return req.status == 200
    except Exception:
        return False


def start_flask_server():
    if is_server_running():
        print("[+] Sentinel Web Server is already running at http://127.0.0.1:5000")
        return

    print("[*] Starting Sentinel Web Application Server on http://127.0.0.1:5000 ...")

    def run_app():
        from app import app
        # Disable reloader in thread mode
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

    server_thread = threading.Thread(target=run_app, daemon=True)
    server_thread.start()

    # Wait briefly for startup
    for _ in range(10):
        if is_server_running():
            print("[+] Sentinel Web Application Server started successfully!")
            break
        time.sleep(0.3)


def start_watchers() -> None:
    """Start the mail trigger layers (extension bridge, arrival watcher,
    title watcher). The agent runs ONLY on real mail events — never on a
    timer, never by scanning an inbox: open-activation by default, and
    arrival auto-triage only if the user opts in via the pet menu.
    """
    from sentinel.watcher import watch_worker

    watch_worker.start()
    print("[+] Mail watcher armed (extension bridge ready on POST /api/watch/open)")

    from sentinel.watcher import load_watch_settings
    from sentinel.arrival_watch import MailpitArrivalWatcher

    if load_watch_settings().get("arrival_watch_enabled", False):
        def handle_arrival(trigger) -> None:
            watch_worker.submit(trigger, timeout=0.5)  # statebus carries the verdict

        MailpitArrivalWatcher(handle_arrival).start()
        print('[+] Arrival watcher ON — incoming Mailpit mail is auto-triaged '
              '(toggle: pet menu "Arrival Watch")')
    else:
        print("[i] Arrival watcher OFF (opt in via the pet menu).")

    if sys.platform != "win32":
        print("[i] Title watcher requires Windows — extension tier remains available.")
        return

    from sentinel.title_watch import Win32TitleWatcher

    if not load_watch_settings().get("title_watch_enabled", True):
        print("[i] Title watcher disabled in sentinel_settings.json (toggle in the pet menu).")
        return

    def handle_open(trigger) -> None:
        watch_worker.submit(trigger, timeout=0.5)  # fire-and-forget; statebus carries the verdict

    Win32TitleWatcher(handle_open).start()
    print("[+] Title watcher polling foreground window (Gmail thread opens)")


def main() -> int:
    print("=========================================================")
    print("  🛡️ SENTINEL GUARD — AI Cybersecurity Desktop Companion")
    print("  Connecting to Backend Engine & Dashboard (http://127.0.0.1:5000)")
    print("=========================================================")

    start_flask_server()
    try:
        start_watchers()
    except Exception as exc:
        print(f"[!] watcher startup failed (guard continues without it): {exc}")

    # Launch PySide6 Desktop Pet Companion
    from overlay import sentinel_pet
    return sentinel_pet.main_guard()


if __name__ == "__main__":
    sys.exit(main())
