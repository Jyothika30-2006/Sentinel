"""Tests for the mail-open watcher (sentinel/watcher.py, sentinel/title_watch.py)
and the /api/watch/open bridge endpoint.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from sentinel.watcher import (
    SURFACE_CONFIDENCE_CAP,
    WatchTrigger,
    WatchWorker,
    _apply_surface_cap,
    _build_surface_eml,
    load_watch_settings,
)
from sentinel.title_watch import parse_gmail_title


# ---------------------------------------------------------------------------
# Tier 3: Gmail tab-title parsing
# ---------------------------------------------------------------------------
class TestParseGmailTitle:
    def test_thread_title(self):
        parsed = parse_gmail_title("Your invoice #4471 - someone@gmail.com - Gmail")
        assert parsed["kind"] == "thread"
        assert parsed["subject"] == "Your invoice #4471"
        assert parsed["unread"] is None

    def test_inbox_title_without_unread(self):
        parsed = parse_gmail_title("Inbox - someone@gmail.com - Gmail")
        assert parsed["kind"] == "view"
        assert parsed["unread"] is None

    def test_inbox_title_with_unread_count(self):
        parsed = parse_gmail_title("Inbox (12) - someone@gmail.com - Gmail")
        assert parsed["kind"] == "view"
        assert parsed["unread"] == 12

    def test_other_views_are_not_threads(self):
        for title in ("Starred - x@gmail.com - Gmail", "Sent - x@gmail.com - Gmail",
                      "Spam (3) - x@gmail.com - Gmail", "Drafts - x@gmail.com - Gmail"):
            assert parse_gmail_title(title)["kind"] == "view", title

    def test_non_gmail_titles_are_ignored(self):
        for title in ("", "Sentinel — Web Dashboard", "Inbox (2) - Outlook",
                      "New Message - Gmail - Mozilla Firefox"):
            assert parse_gmail_title(title)["kind"] == "ignore", title

    def test_suffix_required(self):
        assert parse_gmail_title("Urgent: wire the funds - x@gmail.com")["kind"] == "ignore"


# ---------------------------------------------------------------------------
# Surface-only analysis (Tier 3 honesty contract)
# ---------------------------------------------------------------------------
class TestSurfaceAnalysis:
    def test_surface_eml_has_honest_headers(self):
        raw = _build_surface_eml("Hello <world>", "attacker@evil.example", "body text")
        assert "Subject: Hello <world>" in raw
        assert "From: attacker@evil.example" in raw
        assert "X-Sentinel-Trigger: surface" in raw
        assert raw.endswith("body text")

    def test_surface_eml_unknown_sender_is_not_fabricated(self):
        raw = _build_surface_eml("Some subject", "", "")
        assert "unknown@unknown.invalid" in raw

    def test_surface_eml_sanitizes_newlines_in_subject(self):
        raw = _build_surface_eml("line1\nBcc: victim@x.y", "a@b.c", "")
        # The newline must be flattened into the Subject value — no injected header.
        assert not any(ln.startswith("Bcc:") for ln in raw.splitlines())
        assert any(ln.startswith("Subject: line1") for ln in raw.splitlines())

    def test_confidence_is_capped_for_surface_results(self):
        result = {"confidence_score": 95, "confidence": "High", "summary": "verdict text",
                  "score_breakdown": []}
        trigger = WatchTrigger(source="title", subject="s")
        capped = _apply_surface_cap(result, trigger)
        assert capped["confidence_score"] == SURFACE_CONFIDENCE_CAP
        assert capped["confidence"] != "High"
        assert capped["surface_only"] is True
        assert "surface analysis" in capped["summary"]
        assert any("surface analysis" in b["reason"] for b in capped["score_breakdown"])

    def test_low_confidence_not_raised(self):
        result = {"confidence_score": 40, "confidence": "Low", "summary": "", "score_breakdown": []}
        capped = _apply_surface_cap(result, WatchTrigger(source="title", subject="s"))
        assert capped["confidence_score"] == 40


# ---------------------------------------------------------------------------
# Dedupe keys + worker cache
# ---------------------------------------------------------------------------
class TestWatchTriggerKeys:
    def test_raw_key_is_content_hash(self):
        t1 = WatchTrigger(source="extension", raw_eml="raw body A")
        t2 = WatchTrigger(source="extension", raw_eml="raw body A")
        t3 = WatchTrigger(source="extension", raw_eml="raw body B")
        assert t1.dedupe_key() == t2.dedupe_key()
        assert t1.dedupe_key() != t3.dedupe_key()

    def test_meta_key_uses_subject_and_sender(self):
        a = WatchTrigger(source="title", subject="Invoice", sender="x@y.z")
        b = WatchTrigger(source="title", subject="invoice ", sender="x@y.z")
        c = WatchTrigger(source="title", subject="Invoice", sender="other@y.z")
        assert a.dedupe_key() == b.dedupe_key()
        assert a.dedupe_key() != c.dedupe_key()

    def test_surface_only_flag(self):
        assert WatchTrigger(source="title", subject="s").surface_only is True
        assert WatchTrigger(source="extension", subject="s", raw_eml="...").surface_only is False


class TestWatchWorker:
    def _make_worker(self, monkeypatch, result=None):
        worker = WatchWorker()
        calls = []

        def fake_investigate(path, trigger):
            calls.append(trigger)
            return dict(result or {"verdict": "MALICIOUS", "risk_score": 90,
                                   "confidence_score": 95, "confidence": "High",
                                   "summary": "test"})

        monkeypatch.setattr(worker, "_investigate", fake_investigate)
        monkeypatch.setattr("sentinel.statebus.publish", lambda *a, **k: {})
        return worker, calls

    def test_same_raw_not_investigated_twice(self, monkeypatch):
        worker, calls = self._make_worker(monkeypatch)
        trigger = WatchTrigger(source="extension", subject="s", raw_eml="RAW")
        first = worker.submit(trigger, timeout=10)
        assert first["verdict"] == "MALICIOUS"
        assert "cached" not in first or first.get("cached") is not True

        second = worker.submit(WatchTrigger(source="extension", subject="s", raw_eml="RAW"),
                               timeout=10)
        assert second.get("cached") is True
        assert len(calls) == 1

    def test_different_raw_investigated_again(self, monkeypatch):
        worker, calls = self._make_worker(monkeypatch)
        worker.submit(WatchTrigger(source="extension", raw_eml="A"), timeout=10)
        worker.submit(WatchTrigger(source="extension", raw_eml="B"), timeout=10)
        assert len(calls) == 2

    def test_settings_defaults_present(self):
        settings = load_watch_settings()
        assert settings["title_watch_enabled"] in (True, False)
        assert settings["watch_dedupe_ttl_seconds"] > 0


# ---------------------------------------------------------------------------
# Flask endpoint bridge
# ---------------------------------------------------------------------------
class TestWatchEndpoint:
    @pytest.fixture()
    def client(self, monkeypatch):
        import app as app_module

        # Never run a real investigation from the endpoint tests, and make
        # auth deterministic (the real evidence/api_keys.json may or may not
        # hold an active key on the machine running the tests).
        monkeypatch.setattr(
            app_module.watch_worker, "submit",
            lambda trigger, timeout=20.0: {
                "queued": False, "cached": False, "case_file": trigger.subject or "watched",
                "verdict": "SUSPICIOUS", "risk_score": 45, "confidence": "Medium",
                "confidence_score": 50, "summary": "test result",
                "surface_only": trigger.surface_only, "report_path": "",
            },
        )
        monkeypatch.setattr(app_module.auth_manager, "validate_key", lambda k: True)
        app_module.app.config["TESTING"] = True
        with app_module.app.test_client() as c:
            yield c, app_module

    def test_preflight_has_cors_headers(self, client):
        c, _ = client
        res = c.options("/api/watch/open")
        assert res.status_code == 204
        assert res.headers["Access-Control-Allow-Origin"] == "*"
        assert "X-Session-Token" in res.headers["Access-Control-Allow-Headers"]

    def test_cors_not_leaking_to_other_endpoints(self, client):
        c, _ = client
        res = c.get("/api/status")
        assert "Access-Control-Allow-Origin" not in res.headers

    def test_missing_subject_and_raw_rejected(self, client):
        c, _ = client
        res = c.post("/api/watch/open", json={"source": "extension"})
        assert res.status_code == 400

    def test_extension_payload_returns_verdict(self, client):
        c, _ = client
        res = c.post("/api/watch/open", json={
            "source": "extension", "subject": "Hello", "sender": "a@b.c",
            "thread_id": "AbC123", "raw_eml": "From: a@b.c\nSubject: Hello\n\nbody",
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["verdict"] == "SUSPICIOUS"
        assert data["surface_only"] is False

    def test_title_payload_is_surface_only(self, client):
        c, _ = client
        res = c.post("/api/watch/open", json={"source": "title", "subject": "Opened mail"})
        assert res.status_code == 200
        assert res.get_json()["surface_only"] is True

    def test_auth_enforced_for_remote_callers(self, client, monkeypatch):
        """Remote callers (not on 127.0.0.1) still need a key, even in open mode."""
        c, app_module = client
        monkeypatch.setattr(app_module.auth_manager, "validate_key", lambda k: False)
        res = c.post("/api/watch/open", json={"subject": "x"},
                     environ_base={"REMOTE_ADDR": "203.0.113.5"})
        assert res.status_code == 401

    def test_loopback_callers_need_no_token(self, client, monkeypatch):
        """The browser connector posts from this machine — always allowed."""
        c, app_module = client
        monkeypatch.setattr(app_module.auth_manager, "validate_key", lambda k: False)
        res = c.post("/api/watch/open", json={"subject": "opened mail"})  # REMOTE_ADDR=127.0.0.1
        assert res.status_code == 200
        assert res.get_json()["verdict"] == "SUSPICIOUS"
