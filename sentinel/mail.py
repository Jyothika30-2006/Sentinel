"""Mail connector — how the Sentinel pet reads email, with multiple backends.

The pet shows mail and lets you analyze it. Three backends share one
interface so the pet code never cares which is active:

  * MailpitBackend   — self-hosted, open-source SMTP catcher (MIT). THE
                       recommended path for local demo/testing. You point any
                       script/tool at its SMTP server (port 1025) and every
                       message is captured + readable via REST API (port 8025).
                       Zero cloud, zero Google account, perfect for a demo.
  * ScreenBackend    — reads whatever is currently VISIBLE in the Gmail window
                       by screenshotting it and OCR-ing the text. This is the
                       "via screen" idea. It is intentionally honest about its
                       limits: it returns the current view's text, not a
                       structured inbox, and needs tesseract installed.
  * GmailOAuthBackend — read-only Gmail API (OAuth). STUB for later; safe
                       read-only scope, no send/delete.

PRIVACY: all backends are read-only. Mailpit + screen never leave the machine.
The Gmail OAuth stub will use read-only scope only.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional

import requests


class MailBackend(ABC):
    name = "abstract"

    @abstractmethod
    def list_messages(self, limit: int = 20) -> List[Dict]:
        ...

    @abstractmethod
    def get_message(self, message_id: str) -> Dict:
        ...

    @abstractmethod
    def get_raw(self, message_id: str) -> str:
        """Return the raw .eml source (for feeding to the Sentinel agent)."""


def _strip_html(html: str) -> str:
    txt = re.sub(r"<style.*?</style>|<script.*?</script>", " ", html, flags=re.S | re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = txt.replace("&nbsp;", " ").replace("&#160;", " ")
    txt = txt.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r"\s+", " ", txt).strip()


class MailpitBackend(MailBackend):
    name = "mailpit"

    def __init__(self, base_url: str = "http://localhost:8025") -> None:
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str):
        r = requests.get(f"{self.base_url}{path}", timeout=10)
        r.raise_for_status()
        return r.json()

    def available(self) -> bool:
        try:
            self._get("/api/v1/info")
            return True
        except Exception:
            return False

    def list_messages(self, limit: int = 20) -> List[Dict]:
        data = self._get(f"/api/v1/messages?limit={limit}")
        msgs = data.get("messages", []) if isinstance(data, dict) else []
        out = []
        for m in msgs:
            frm = m.get("From") or {}
            to0 = (m.get("To") or [{}])
            out.append({
                "id": m.get("ID"),
                "subject": m.get("Subject", "(no subject)"),
                "from": frm.get("Name") or frm.get("Address", "?"),
                "to": to0[0].get("Address", "?") if to0 else "?",
                "created": m.get("Created"),
            })
        return out

    def get_message(self, message_id: str) -> Dict:
        m = self._get(f"/api/v1/message/{message_id}")
        if not isinstance(m, dict):
            return {}
        return {
            "id": m.get("ID"),
            "subject": m.get("Subject", "(no subject)"),
            "from": (m.get("From") or {}).get("Address", "?"),
            "to": [(t or {}).get("Address") for t in (m.get("To") or [])],
            "date": m.get("Date"),
            "headers": m.get("Headers", {}),
            "text": m.get("Text") or _strip_html(m.get("HTML") or "") or "",
            "html": m.get("HTML"),
            "attachments": [a.get("FileName") for a in (m.get("Attachments") or [])],
        }

    def get_raw(self, message_id: str) -> str:
        r = requests.get(f"{self.base_url}/api/v1/message/{message_id}/raw", timeout=10)
        r.raise_for_status()
        return r.text


class ScreenBackend(MailBackend):
    """OCR the visible Gmail window. Fragile by nature — documented honestly."""

    name = "screen"

    def __init__(self, window_name: str = "Gmail") -> None:
        self.window_name = window_name

    @staticmethod
    def _find_window_id() -> Optional[str]:
        import shutil

        if not shutil.which("xdotool"):
            return None
        try:
            out = subprocess.run(
                ["xdotool", "search", "--name", "Gmail"],
                capture_output=True, text=True, timeout=3,
            ).stdout.strip()
            return out.splitlines()[0] if out else None
        except Exception:
            return None

    def _screenshot(self) -> Optional[str]:
        import shutil

        wid = self._find_window_id()
        if not wid or not shutil.which("import"):  # ImageMagick
            return None
        out = tempfile.mktemp(suffix=".png")
        try:
            subprocess.run(["import", "-window", wid, out], timeout=10, check=True)
            return out
        except Exception:
            return None

    def _ocr(self, png_path: str) -> str:
        import shutil

        if not shutil.which("tesseract"):
            return ""
        try:
            r = subprocess.run(
                ["tesseract", png_path, "stdout"], capture_output=True, text=True, timeout=30
            )
            return r.stdout.strip()
        except Exception:
            return ""

    def grab_current_view(self) -> str:
        png = self._screenshot()
        if not png:
            return (
                "[screen backend] could not capture the Gmail window "
                "(needs xdotool + ImageMagick 'import'). Use --mail mailpit instead."
            )
        text = self._ocr(png)
        try:
            Path(png).unlink(missing_ok=True)
        except Exception:
            pass
        if not text:
            return "[screen backend] screenshot captured but OCR failed (install tesseract)."
        return text

    def list_messages(self, limit: int = 20) -> List[Dict]:
        return [{
            "id": "screen-current",
            "subject": "(current Gmail view via OCR)",
            "from": "screen",
            "to": "screen",
            "created": "",
        }]

    def get_message(self, message_id: str) -> Dict:
        return {"id": message_id, "subject": "(screen OCR)", "from": "screen",
                "to": [], "date": "", "headers": {}, "text": self.grab_current_view(),
                "html": None, "attachments": []}

    def get_raw(self, message_id: str) -> str:
        text = self.grab_current_view()
        return "Subject: (screen OCR of Gmail window)\nFrom: screen-capture@local\n\n" + text


class GmailOAuthBackend(MailBackend):
    name = "gmail-oauth"

    def _unimplemented(self):
        raise NotImplementedError(
            "Gmail OAuth backend is a stub. Later: use google-auth + "
            "google-api-python-client with READ-ONLY scope "
            "https://www.googleapis.com/auth/gmail.readonly."
        )

    def list_messages(self, limit: int = 20) -> List[Dict]:
        self._unimplemented()

    def get_message(self, message_id: str) -> Dict:
        self._unimplemented()

    def get_raw(self, message_id: str) -> str:
        self._unimplemented()


def get_backend(kind: str = "mailpit", **cfg) -> MailBackend:
    kind = kind.lower()
    if kind in ("mailpit", "mailhog"):
        return MailpitBackend(base_url=cfg.get("base_url", "http://localhost:8025"))
    if kind in ("screen", "ocr", "gmail-screen"):
        return ScreenBackend(window_name=cfg.get("window_name", "Gmail"))
    if kind in ("gmail", "oauth", "gmail-oauth"):
        return GmailOAuthBackend()
    raise ValueError(f"unknown mail backend: {kind}")
