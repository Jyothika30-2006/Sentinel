"""Tests for arrival auto-triage (sentinel/arrival_watch.py) and the
extended /api/watch/open source whitelist.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from sentinel.arrival_watch import new_arrivals
from sentinel.watcher import DEFAULT_SETTINGS, WatchTrigger, WatchWorker


def _msg(id_, subject="s"):
    return {"id": id_, "subject": subject, "from": "a@b.c"}


# ---------------------------------------------------------------------------
# Arrival diffing
# ---------------------------------------------------------------------------
class TestNewArrivals:
    def test_first_observation_seeds_baseline_without_backscan(self):
        fresh, seen = new_arrivals([_msg("1"), _msg("2")], None)
        assert fresh == []
        assert seen == {"1", "2"}

    def test_new_message_detected(self):
        _, seen = new_arrivals([_msg("1")], None)
        fresh, seen2 = new_arrivals([_msg("2"), _msg("1")], seen)
        assert [m["id"] for m in fresh] == ["2"]
        assert seen2 == {"1", "2"}

    def test_unchanged_inbox_yields_nothing(self):
        _, seen = new_arrivals([_msg("1"), _msg("2")], None)
        fresh, seen2 = new_arrivals([_msg("2"), _msg("1")], seen)
        assert fresh == []
        assert seen2 == seen

    def test_empty_mailbox_keeps_seen_set(self):
        _, seen = new_arrivals([_msg("1")], None)
        fresh, seen2 = new_arrivals([], seen)
        assert fresh == []
        assert seen2 == {"1"}

    def test_message_without_id_is_ignored(self):
        _, seen = new_arrivals([_msg("1")], None)
        fresh, _ = new_arrivals([{"subject": "no id"}, _msg("1")], seen)
        assert fresh == []

    def test_id_reappearance_does_not_retrigger(self):
        _, seen = new_arrivals([_msg("1")], None)
        fresh, seen2 = new_arrivals([], seen)          # mail leaves the top list
        fresh2, _ = new_arrivals([_msg("1")], seen2)   # and comes back
        assert fresh == [] and fresh2 == []

    def test_arrival_settings_default_off(self):
        assert DEFAULT_SETTINGS["arrival_watch_enabled"] is False


# ---------------------------------------------------------------------------
# Regression: materialized watch files must keep their \r\n headers intact
# ---------------------------------------------------------------------------
class TestMaterializeLineEndings:
    def test_crlf_raw_keeps_all_headers(self, monkeypatch):
        from sentinel.watcher import WatchWorker

        raw = ("From: PayPal Security <security@paypa1-verify.tk>\r\n"
               "Subject: Urgent\r\n"
               "Authentication-Results: mail.test.local; spf=fail smtp.mailfrom=x.tk\r\n"
               "\r\n"
               "body here\r\n")

        worker = WatchWorker()
        path = worker._materialize(WatchTrigger(source="mailpit", subject="s", raw_eml=raw))
        data = Path(path).read_bytes()
        assert b"\r\r\n" not in data, "double CRLF corrupts header parsing"

        from sentinel.tools import parse_headers
        h = parse_headers.parse_headers(path)
        assert h["auth"]["spf"] == "fail"
        assert "paypa1-verify.tk" in h["From"]


# ---------------------------------------------------------------------------
# Endpoint accepts the new trigger sources
# ---------------------------------------------------------------------------
class TestArrivalEndpointSources:
    @pytest.fixture()
    def client(self, monkeypatch):
        import app as app_module

        captured = {}

        def fake_submit(trigger, timeout=20.0):
            captured["trigger"] = trigger
            return {"queued": False, "cached": False, "case_file": trigger.subject or "w",
                    "verdict": "SAFE", "risk_score": 0, "confidence": "Medium",
                    "confidence_score": 50, "summary": "ok", "surface_only": False,
                    "report_path": ""}

        monkeypatch.setattr(app_module.watch_worker, "submit", fake_submit)
        monkeypatch.setattr(app_module.auth_manager, "validate_key", lambda k: True)
        app_module.app.config["TESTING"] = True
        with app_module.app.test_client() as c:
            yield c, app_module, captured

    def test_extension_arrival_source_passthrough(self, client):
        c, _, captured = client
        res = c.post("/api/watch/open", json={"source": "extension-arrival",
                                              "subject": "New mail landed"})
        assert res.status_code == 200
        assert captured["trigger"].source == "extension-arrival"

    def test_mailpit_source_passthrough(self, client):
        c, _, captured = client
        res = c.post("/api/watch/open", json={"source": "mailpit", "subject": "x",
                                              "raw_eml": "From: a@b.c\n\nhi"})
        assert res.status_code == 200
        assert captured["trigger"].source == "mailpit"
        assert captured["trigger"].surface_only is False

    def test_unknown_source_coerced_to_extension(self, client):
        c, _, captured = client
        res = c.post("/api/watch/open", json={"source": "bogus", "subject": "x"})
        assert res.status_code == 200
        assert captured["trigger"].source == "extension"
