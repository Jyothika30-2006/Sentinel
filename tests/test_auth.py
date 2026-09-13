"""Unit tests for Sentinel API Key Authentication & Management."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is importable
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from sentinel.auth import APIKeyManager


def test_api_key_lifecycle(tmp_path):
    storage_file = tmp_path / "sentinel_api_keys.json"
    mgr = APIKeyManager(storage_file)

    # Initial status
    status = mgr.get_status()
    assert status["status"] == "unconfigured"
    assert mgr.validate_key("random_key") is True  # unconfigured mode permits open access

    # Generate Key
    raw_key, record = mgr.generate_key()
    assert raw_key.startswith("sk_sentinel_")
    assert record["status"] == "active"
    assert record["masked"].startswith("sk_sentinel_")

    # Validate Key
    assert mgr.validate_key(raw_key) is True
    assert mgr.validate_key("invalid_key_payload") is False
    assert mgr.validate_key(None) is False

    # Status check after creation
    status_active = mgr.get_status()
    assert status_active["status"] == "active"
    assert status_active["masked"] == record["masked"]

    # Revoke Key
    revoked = mgr.revoke_key()
    assert revoked is True
    assert mgr.validate_key(raw_key) is False  # Revoked key must fail validation

    status_revoked = mgr.get_status()
    assert status_revoked["status"] == "revoked"

    # Regenerate Key
    new_raw_key, new_record = mgr.generate_key()
    assert new_raw_key.startswith("sk_sentinel_")
    assert new_raw_key != raw_key
    assert mgr.validate_key(new_raw_key) is True
    assert mgr.validate_key(raw_key) is False  # Old key remains invalid


def test_app_open_access_endpoints(tmp_path):
    """Test Flask app API endpoints are now open access (no API key required).

    The require_api_key decorator was removed per user request to allow
    Sentinel to run without activation/API key for local use.
    """
    from app import app

    client = app.test_client()

    # All endpoints should respond 200 even without any Authorization header
    res_no_key = client.get("/api/reports")
    assert res_no_key.status_code == 200

    res_ledger = client.get("/api/ledger")
    assert res_ledger.status_code == 200

    res_status = client.get("/api/status")
    assert res_status.status_code == 200

