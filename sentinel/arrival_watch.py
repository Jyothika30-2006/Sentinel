"""Arrival watcher — auto-triage every INCOMING mail (opt-in mode).

Unlike the open-activation tiers, this watches for mail ARRIVING and runs
the deterministic triage pipeline on each new message automatically.
Currently implemented backend:

  * Mailpit — the self-hosted SMTP catcher used for local demos. Its REST
    API lists messages with stable content-hash IDs, so new arrivals are a
    simple set-diff between polls. Raw source comes from the existing
    MailpitBackend.get_raw().

Gmail arrival without tokens is handled by the browser extension instead
(extension/content.js watches the inbox list and posts
source="extension-arrival" to /api/watch/open) — an HTTP-free in-process
watcher cannot see Gmail without credentials.

Activation contract: this watcher submits raw triggers; the shared
WatchWorker applies dedupe/caching, so a mail that arrives AND is later
opened is analyzed exactly once. Toggle: `arrival_watch_enabled` in
sentinel_settings.json (pet menu: "Arrival Watch").
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

from .mail import MailpitBackend
from .watcher import WatchTrigger, load_watch_settings

POLL_SECONDS = 3.0


# ---------------------------------------------------------------------------
# Pure diff logic (unit-testable, backend-agnostic)
# ---------------------------------------------------------------------------
def new_arrivals(messages: List[Dict], seen: Optional[Set[str]]) -> Tuple[List[Dict], Set[str]]:
    """Return (new_messages, updated_seen_set).

    `seen=None` (or empty) means "first observation": seed the baseline and
    return no arrivals, so pre-existing inbox content is never back-scanned
    — only messages that arrive after startup. An empty mailbox leaves the
    seen-set untouched.
    """
    ids = {str(m.get("id")) for m in messages if m.get("id")}
    if not seen:
        # First observation (None or empty): baseline seed, no back-scan.
        return [], set(ids)
    fresh = [m for m in messages if m.get("id") and str(m.get("id")) not in seen]
    return fresh, seen | ids


class MailpitArrivalWatcher:
    """Daemon thread polling Mailpit for incoming messages."""

    def __init__(self, on_arrival: Callable[[WatchTrigger], None],
                 base_url: str = "http://localhost:8025",
                 poll_seconds: float = POLL_SECONDS) -> None:
        self.on_arrival = on_arrival
        self.backend = MailpitBackend(base_url=base_url)
        self.poll_seconds = poll_seconds
        self._seen: Optional[Set[str]] = None
        self._unavailable_logged = False
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        t = threading.Thread(target=self._loop, name="sentinel-arrival-watch", daemon=True)
        t.start()

    @property
    def running(self) -> bool:
        return self._started

    def _enabled(self) -> bool:
        return bool(load_watch_settings().get("arrival_watch_enabled", False))

    def _loop(self) -> None:
        while True:
            try:
                if self._enabled():
                    self._poll_once()
                else:
                    self._seen = None  # re-seed when re-enabled
            except Exception:
                pass  # a watcher must never take the host process down
            time.sleep(self.poll_seconds)

    def _poll_once(self) -> None:
        if not self.backend.available():
            if not self._unavailable_logged:
                print("[arrival-watch] Mailpit not reachable on "
                      f"{self.backend.base_url} — will keep retrying.")
                self._unavailable_logged = True
            return
        self._unavailable_logged = False

        messages = self.backend.list_messages(limit=20)
        fresh, self._seen = new_arrivals(messages, self._seen)
        for msg in fresh:
            trigger = self._to_trigger(msg)
            if trigger is not None:
                self.on_arrival(trigger)

    def _to_trigger(self, msg: Dict) -> Optional[WatchTrigger]:
        try:
            raw = self.backend.get_raw(str(msg.get("id")))
        except Exception:
            raw = None
        return WatchTrigger(
            source="mailpit",
            subject=str(msg.get("subject") or "(no subject)"),
            sender=str(msg.get("from") or ""),
            thread_id=str(msg.get("id") or ""),
            raw_eml=raw,
        )


# ---------------------------------------------------------------------------
# Manual test entry: python -m sentinel.arrival_watch [--once]
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="sentinel.arrival_watch",
                                description="Auto-triage incoming Mailpit messages")
    p.add_argument("--base-url", default="http://localhost:8025")
    p.add_argument("--once", action="store_true", help="list current Mailpit inbox and exit")
    args = p.parse_args(argv)

    backend = MailpitBackend(base_url=args.base_url)
    if not backend.available():
        print(f"Mailpit not reachable at {args.base_url} (start it first).")
        return 1
    msgs = backend.list_messages(limit=20)
    print(f"{len(msgs)} message(s) in Mailpit:")
    for m in msgs:
        print(f"  - {m['id'][:12]}  {m['from']!r:35} {m['subject']!r}")
    if args.once:
        return 0

    from .watcher import watch_worker

    def handle(trigger: WatchTrigger) -> None:
        print(f"[arrival] {trigger.subject!r} from {trigger.sender!r} — auto-triaging")
        res = watch_worker.submit(trigger, timeout=0.5)
        if res.get("queued"):
            print("[arrival] queued (verdict lands on the statebus)")
        else:
            print(f"[arrival] verdict: {res.get('verdict')} ({res.get('confidence_score', '?')}%)")

    watcher = MailpitArrivalWatcher(handle, base_url=args.base_url)
    watcher.start()
    print("[arrival-watch] watching for incoming mail — Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
