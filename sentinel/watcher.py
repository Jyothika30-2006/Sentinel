"""Mail watcher — activates the agent on mail events.

Two activation models share this core:

  * OPEN-activation (default): Tier 1 "extension" / Tier 3 "title" —
    the agent runs ONLY when the user actually opens a message.
  * ARRIVAL-activation (opt-in): "mailpit" (sentinel/arrival_watch.py) and
    "extension-arrival" (the extension's inbox watcher) — every incoming
    message is auto-triaged as it lands. Opt in via the pet menu
    ("Arrival Watch") or `arrival_watch_enabled` in sentinel_settings.json.

Trigger sources: "extension" | "extension-arrival" | "mailpit" | "title".

Arrival triggers run the same deterministic pipeline (fast, no LLM quota);
re-opening a mail that arrival already scanned hits the TTL cache instead
of re-analyzing. Tier 3 "title" remains surface-only with capped confidence
— the honesty rule resolve_origin applies to the Gmail IP-hiding problem:
never fabricate certainty.
"""
from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import statebus

_REPO_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_FILE = _REPO_ROOT / "sentinel_settings.json"

# Surface-only verdicts (no raw headers/attachments available) never claim
# more confidence than this.
SURFACE_CONFIDENCE_CAP = 60

DEFAULT_SETTINGS = {
    "title_watch_enabled": True,
    "arrival_watch_enabled": False,   # opt-in: scan every incoming mail
    "watch_dedupe_ttl_seconds": 600,
}


# ---------------------------------------------------------------------------
# Settings (sentinel_settings.json — shared with the desktop pet)
# ---------------------------------------------------------------------------
def load_watch_settings() -> Dict[str, Any]:
    try:
        cfg = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        cfg = {}
    out = dict(DEFAULT_SETTINGS)
    out.update({k: cfg[k] for k in DEFAULT_SETTINGS if k in cfg})
    return out


def save_watch_setting(key: str, value: Any) -> None:
    """Persist one watcher key while preserving the pet's own keys."""
    try:
        cfg = json.loads(SETTINGS_FILE.read_text(encoding="utf-8")) if SETTINGS_FILE.exists() else {}
    except Exception:
        cfg = {}
    cfg[key] = value
    try:
        SETTINGS_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Trigger model
# ---------------------------------------------------------------------------
@dataclass
class WatchTrigger:
    source: str                      # "extension" | "extension-arrival" | "mailpit" | "title"
    subject: str = ""
    sender: str = ""
    thread_id: str = ""
    raw_eml: Optional[str] = None    # full RFC822 source when the tier can get it
    body_text: str = ""              # visible-body fallback for surface analysis
    ts: float = field(default_factory=time.time)

    @property
    def surface_only(self) -> bool:
        return not self.raw_eml

    def dedupe_key(self) -> str:
        if self.raw_eml:
            return "raw:" + hashlib.sha256(self.raw_eml.encode("utf-8", errors="replace")).hexdigest()
        return f"meta:{(self.subject or '').strip().lower()}|{(self.sender or '').strip().lower()}"


def _build_surface_eml(subject: str, sender: str, body_text: str = "") -> str:
    """Minimal RFC822 message for tiers that cannot read the raw source.

    Deliberately honest headers: an unknown sender is marked unknown so the
    analysis cannot accidentally trust a fabricated identity.
    """
    from_addr = sender.strip() if sender and "@" in sender else "Unknown Sender <unknown@unknown.invalid>"
    subj = (subject or "(opened mail — subject not visible)").replace("\n", " ")
    lines = [
        f"From: {from_addr}",
        f"Subject: {subj}",
        f"Date: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}",
        "X-Sentinel-Trigger: surface (no account access — headers unavailable)",
        "MIME-Version: 1.0",
        'Content-Type: text/plain; charset="utf-8"',
        "",
        body_text.strip(),
    ]
    return "\n".join(lines)


def _apply_surface_cap(result: Dict[str, Any], trigger: WatchTrigger) -> Dict[str, Any]:
    """Cap confidence and label surface-only results explicitly."""
    conf = int(result.get("confidence_score") or 0)
    conf = min(conf, SURFACE_CONFIDENCE_CAP)
    result["confidence_score"] = conf
    result["confidence"] = "High" if conf >= 80 else "Medium" if conf >= 50 else "Low"
    note = (f"surface analysis — raw headers unavailable ({trigger.source} watch, "
            f"no account access); confidence capped at {SURFACE_CONFIDENCE_CAP}%")
    result["surface_only"] = True
    result["summary"] = f"[{note}] {result.get('summary') or ''}".strip()
    breakdown = result.setdefault("score_breakdown", [])
    breakdown.append({"category": "watcher", "points": 0, "reason": note})
    return result


# ---------------------------------------------------------------------------
# Worker: one investigation at a time, TTL dedupe, cached verdicts
# ---------------------------------------------------------------------------
class WatchWorker:
    def __init__(self) -> None:
        self._queue: "queue.Queue[tuple]" = queue.Queue()
        self._lock = threading.Lock()
        self._cache: Dict[str, Dict[str, Any]] = {}   # dedupe key -> {"ts", "result"}
        self._busy = threading.Event()
        self._started = False
        self._last: Optional[Dict[str, Any]] = None

    # --- lifecycle ----------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        t = threading.Thread(target=self._loop, name="sentinel-watch", daemon=True)
        t.start()

    @property
    def running(self) -> bool:
        return self._started

    def _loop(self) -> None:
        while True:
            job_id, trigger, done = self._queue.get()
            try:
                result = self._run(trigger)
            except Exception as exc:  # never kill the worker thread
                result = {"error": f"watch investigation failed: {exc}"}
            result.setdefault("case_file", (trigger.subject or "watched mail"))
            with self._lock:
                self._cache[trigger.dedupe_key()] = {"ts": time.time(), "result": result}
                self._last = dict(result)
                self._prune_cache()
            self._busy.clear()
            if done is not None:
                done["event"].set()

    def last_result(self) -> Optional[Dict[str, Any]]:
        """Full result dict of the most recent watch investigation (or None)."""
        with self._lock:
            return dict(self._last) if self._last else None

    def _prune_cache(self) -> None:
        ttl = load_watch_settings().get("watch_dedupe_ttl_seconds", 600)
        now = time.time()
        for k in [k for k, v in self._cache.items() if now - v["ts"] > ttl]:
            self._cache.pop(k, None)

    # --- public API ---------------------------------------------------
    def submit(self, trigger: WatchTrigger, timeout: float = 20.0) -> Dict[str, Any]:
        """Queue a trigger. Returns the result, or {'queued': True} if the
        caller's wait budget expired (verdict still lands on the statebus)."""
        self.start()

        key = trigger.dedupe_key()
        with self._lock:
            hit = self._cache.get(key)
        if hit and time.time() - hit["ts"] <= load_watch_settings().get("watch_dedupe_ttl_seconds", 600):
            cached = dict(hit["result"])
            cached["cached"] = True
            return cached

        if self._busy.is_set():
            # Another investigation is running; enqueue and report async.
            done = {"event": threading.Event()}
            self._queue.put((id(trigger), trigger, done))
            return {"queued": True, "case_file": trigger.subject or "watched mail"}

        self._busy.set()
        done = {"event": threading.Event()}
        self._queue.put((id(trigger), trigger, done))
        if done["event"].wait(timeout):
            with self._lock:
                hit = self._cache.get(key)
            if hit:
                return dict(hit["result"])
            return {"queued": True, "case_file": trigger.subject or "watched mail"}
        return {"queued": True, "case_file": trigger.subject or "watched mail"}

    # --- investigation --------------------------------------------------
    def _run(self, trigger: WatchTrigger) -> Dict[str, Any]:
        subject = trigger.subject or "(opened mail — subject not visible)"
        statebus.publish(
            state="investigating",
            risk=0,
            verdict=None,
            message=f'You opened "{subject}" — Sentinel activated ({trigger.source} watch)',
            extra={"case_file": subject, "trigger_source": trigger.source},
        )

        email_path = self._materialize(trigger)
        result = self._investigate(email_path, trigger)
        result["trigger"] = {
            "source": trigger.source,
            "subject": trigger.subject,
            "sender": trigger.sender,
            "thread_id": trigger.thread_id,
            "surface_only": trigger.surface_only,
        }
        if trigger.surface_only:
            result = _apply_surface_cap(result, trigger)

        statebus.publish(
            state="verdict",
            verdict=result.get("verdict"),
            risk=result.get("risk_score", 0),
            message=(f"{result.get('verdict')} ({result.get('confidence_score', '?')}%) — "
                     f'opened "{subject}" [{trigger.source} watch]'),
            extra={"case_file": subject, "trigger_source": trigger.source, "watch_result": True},
        )
        return result

    def _materialize(self, trigger: WatchTrigger) -> str:
        if trigger.raw_eml:
            content = trigger.raw_eml
        else:
            content = _build_surface_eml(trigger.subject, trigger.sender, trigger.body_text)
        uploads = _REPO_ROOT / "uploads"
        uploads.mkdir(exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        path = uploads / f"watch_{stamp}.eml"
        # Write BYTES: raw mail sources use \r\n line endings, and text-mode
        # writes would translate them to \r\r\n on Windows — the email parser
        # then treats the first header line as the end of the header block.
        path.write_bytes(content.encode("utf-8", errors="replace"))
        return str(path)

    def _investigate(self, email_path: str, trigger: WatchTrigger) -> Dict[str, Any]:
        """Same pipeline the dashboard/pet use (orchestrator), no LLM dependency."""
        from pathlib import Path as _P

        from .orchestrator import orchestrator
        from .report import write_report

        result = orchestrator.run_investigation(email_path, auto_confirm=True)
        result["email_path"] = email_path
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        try:
            result["report_path"] = write_report(
                email_path=email_path,
                verdict=result["verdict"],
                confidence=result.get("confidence_score", 90),
                evidence=[e.get("reason", "") for e in result.get("score_breakdown", [])],
                risk_events=[],
                observations=[result.get("summary", "")],
                ledger_ref=result.get("ledger_block", {}),
            )
        except Exception:
            pass
        return result


# Module-level singleton (started lazily by submit()/run_guard).
watch_worker = WatchWorker()
