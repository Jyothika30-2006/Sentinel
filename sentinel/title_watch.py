"""Tier 3 — window-title mail-open watcher (no credentials, honest limits).

Watches the FOREGROUND window title. Gmail's browser tab reveals two useful,
tokenless signals:

  * Opening a conversation changes the tab title to ``«Subject» - x@gmail.com - Gmail``
  * Reading mail drops the unread count in ``Inbox (N) - x@gmail.com - Gmail``

The watcher triggers ONLY on the thread-title signal (an unread-count drop
coincides with a title change when a mail is opened in the same tab, so a
separate trigger would double-fire). No raw message source is available at
this tier, so the watcher submits a surface-only WatchTrigger and the
pipeline caps confidence (see sentinel/watcher.py).

Accuracy contract: this tier can detect *that* a mail was opened and its
subject, but not its headers or attachments. Verdicts are labeled
"surface analysis" and never claim high confidence.
"""
from __future__ import annotations

import re
import sys
import threading
import time
from typing import Callable, Dict, Optional

from .watcher import WatchTrigger, load_watch_settings

POLL_SECONDS = 2.0

# Gmail's list-view tab titles ("Inbox", localized variants, and utility
# views). Everything else that ends in "- Gmail" is treated as a thread title.
_VIEW_WORDS = (
    "inbox", "starred", "snoozed", "sent", "drafts", "important", "chats",
    "scheduled", "all mail", "spam", "trash", "bin", "categories", "social",
    "updates", "promotions", "forums", "search", "labels", "settings", "themes",
    "contacts", "tasks", "google contacts", "label:",
)

_UNREAD_RE = re.compile(r"\((\d+)\)")


def parse_gmail_title(title: str) -> Dict[str, object]:
    """Classify a browser tab title.

    Returns {"kind": "thread"|"view"|"ignore", "subject": str|None,
    "unread": int|None}.

    Known limitation: on non-English Gmail UIs the utility-view words differ,
    so a list view may be misread as a thread title. The unread-count signal
    and the "- Gmail" suffix remain reliable.
    """
    title = (title or "").strip()
    if not title or not title.lower().endswith("- gmail"):
        return {"kind": "ignore", "subject": None, "unread": None}

    head = title[: -len("- Gmail")].strip().rstrip("-").strip()
    segments = [s.strip() for s in head.split(" - ")]
    first = segments[0] if segments else ""
    first_low = first.lower()

    m = _UNREAD_RE.search(first)
    unread = int(m.group(1)) if m else None

    if any(first_low.startswith(w) or first_low == w for w in _VIEW_WORDS):
        return {"kind": "view", "subject": None, "unread": unread}
    if not first:
        return {"kind": "ignore", "subject": None, "unread": None}
    return {"kind": "thread", "subject": first, "unread": unread}


# ---------------------------------------------------------------------------
# Win32 foreground-title polling (ctypes — no pywin32 dependency)
# ---------------------------------------------------------------------------
def _get_foreground_title() -> str:
    if sys.platform != "win32":
        return ""
    import ctypes

    user32 = ctypes.windll.user32
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return ""
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def ocr_foreground_window() -> Optional[str]:
    """Best-effort OCR of the foreground window (optional dependencies).

    Requires pillow + pytesseract + the tesseract binary. Returns None when
    any piece is missing — the pipeline then runs metadata-only surface
    analysis instead.
    """
    try:
        from PIL import ImageGrab  # noqa: WPS433 (optional dep)
        import pytesseract  # noqa: WPS433 (optional dep)
    except Exception:
        return None
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        import ctypes.wintypes

        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        rect = ctypes.wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        img = ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom))
        return pytesseract.image_to_string(img) or None
    except Exception:
        return None


class Win32TitleWatcher:
    """Daemon thread polling the foreground window title for Gmail opens."""

    def __init__(self, on_open: Callable[[WatchTrigger], None],
                 poll_seconds: float = POLL_SECONDS) -> None:
        self.on_open = on_open
        self.poll_seconds = poll_seconds
        self._last_thread_subject: Optional[str] = None
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        t = threading.Thread(target=self._loop, name="sentinel-title-watch", daemon=True)
        t.start()

    @property
    def running(self) -> bool:
        return self._started

    def _enabled(self) -> bool:
        return bool(load_watch_settings().get("title_watch_enabled", True))

    def _loop(self) -> None:
        while True:
            try:
                if self._enabled():
                    self._poll_once()
                else:
                    # Reset so re-enabling doesn't replay the old title.
                    self._last_thread_subject = None
            except Exception:
                pass  # a watcher must never take the host process down
            time.sleep(self.poll_seconds)

    def _poll_once(self) -> None:
        title = _get_foreground_title()
        if not title:
            return
        parsed = parse_gmail_title(title)
        if parsed["kind"] != "thread":
            return
        subject = str(parsed["subject"])
        if subject == self._last_thread_subject:
            return  # same conversation still open — not a new open event
        self._last_thread_subject = subject
        trigger = WatchTrigger(source="title", subject=subject, sender="",
                               thread_id="", raw_eml=None)
        self.on_open(trigger)


# ---------------------------------------------------------------------------
# Manual test entry: python -m sentinel.title_watch [--once]
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="sentinel.title_watch",
                                description="Watch foreground Gmail tab titles (Tier 3)")
    p.add_argument("--once", action="store_true", help="print the current title parse and exit")
    p.add_argument("--interval", type=float, default=POLL_SECONDS)
    args = p.parse_args(argv)

    if args.once:
        title = _get_foreground_title()
        print(f"foreground title: {title!r}")
        print(f"parsed: {parse_gmail_title(title)}")
        return 0

    from .watcher import watch_worker

    def handle(trigger: WatchTrigger) -> None:
        print(f"[title-watch] open detected: {trigger.subject!r} — submitting")
        res = watch_worker.submit(trigger, timeout=0.5)
        if res.get("queued"):
            print("[title-watch] investigation queued (verdict will land on the statebus)")
        else:
            print(f"[title-watch] verdict: {res.get('verdict')} "
                  f"({res.get('confidence_score', '?')}%) cached={res.get('cached', False)}")

    watcher = Win32TitleWatcher(handle, poll_seconds=args.interval)
    watcher.start()
    print(f"[title-watch] polling foreground titles every {args.interval}s — Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
