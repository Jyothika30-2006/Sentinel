"""Unit tests for Sentinel Guard Production Email OTP Activation & Account Recovery."""
import json
import time
import pytest
from pathlib import Path

from sentinel.email_activation import EmailActivationManager, OTP_TTL_SECONDS
from sentinel.auth import APIKeyManager


@pytest.fixture
def tmp_activation(tmp_path):
    act_file = tmp_path / "test_activation.json"
    mgr = EmailActivationManager(storage_path=act_file)
    return mgr


def test_request_activation_hashes_otp(tmp_activation):
    mgr = tmp_activation
    email = "user@test.local"

    mgr.request_activation(email)
    st = mgr.get_status()

    assert st["state"] == "ACTIVATION_PENDING"
    assert mgr.data["pending_otp"]["email"] == email

    # Verify salted hash is stored, NOT plaintext
    salt = mgr.data["pending_otp"]["salt"]
    hashed = mgr.data["pending_otp"]["hash"]

    assert isinstance(salt, str) and len(salt) == 32
    assert isinstance(hashed, str) and len(hashed) == 64
    assert "raw_otp" not in mgr.data["pending_otp"]


def test_rate_limiting_resend(tmp_activation):
    mgr = tmp_activation
    email = "user@test.local"

    mgr.request_activation(email)

    # Immediate second request should raise rate limit error
    with pytest.raises(ValueError, match="Please wait"):
        mgr.request_activation(email)


def test_verification_attempt_counter_and_lock(tmp_activation):
    mgr = tmp_activation
    email = "user@test.local"

    mgr.request_activation(email)

    # 4 invalid attempts should raise error with remaining attempts count
    for i in range(1, 5):
        with pytest.raises(ValueError, match="Invalid verification code"):
            mgr.verify_activation(email, "000000")

    # 5th invalid attempt should lock the request
    with pytest.raises(ValueError, match="Maximum verification attempts exceeded"):
        mgr.verify_activation(email, "000000")

    assert mgr.get_status()["state"] == "LOCKED"


def test_successful_otp_verification_issues_session_token(tmp_activation):
    mgr = tmp_activation
    email = "user@test.local"

    # Manually inspect outbox mail file to retrieve generated test OTP
    mgr.request_activation(email)
    outbox_files = list(mgr.outbox_dir.glob("*_activation.txt"))
    assert len(outbox_files) >= 1

    content = outbox_files[-1].read_text(encoding="utf-8")
    otp_line = [l for l in content.splitlines() if "verification code is:" in l][0]
    raw_otp = otp_line.split(":")[-1].strip()

    session_token = mgr.verify_activation(email, raw_otp)

    assert session_token.startswith("sk_session_")
    assert mgr.is_activated()
    assert mgr.get_status()["state"] == "ACTIVE"
    assert mgr.validate_session_token(session_token) is True


def test_account_recovery_flow(tmp_activation):
    mgr = tmp_activation
    email = "recovered@test.local"

    # Admin activate first
    token1 = mgr.admin_force_activate(email)
    assert mgr.is_activated()

    # Now request recovery
    mgr.request_recovery(email)
    st = mgr.get_status()
    assert st["state"] == "RECOVERY_PENDING"

    # Retrieve recovery OTP from outbox
    outbox_files = list(mgr.outbox_dir.glob("*_recovery.txt"))
    content = outbox_files[-1].read_text(encoding="utf-8")
    otp_line = [l for l in content.splitlines() if "recovery code is:" in l][0]
    raw_otp = otp_line.split(":")[-1].strip()

    # Verify recovery OTP
    token2 = mgr.verify_recovery(email, raw_otp)
    assert token2.startswith("sk_session_")
    assert mgr.is_activated()
    assert mgr.validate_session_token(token2) is True


def test_unverified_email_recovery_fails(tmp_activation):
    mgr = tmp_activation

    with pytest.raises(ValueError, match="We can't verify ownership of this email"):
        mgr.request_recovery("unverified@test.local")


def test_session_revocation_logout(tmp_activation):
    mgr = tmp_activation
    email = "user@test.local"

    token = mgr.admin_force_activate(email)
    assert mgr.validate_session_token(token) is True

    mgr.revoke_session(token)
    assert mgr.is_activated() is False
    assert mgr.validate_session_token(token) is False
