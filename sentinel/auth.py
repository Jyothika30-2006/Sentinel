"""API Key Authentication & Management Module.

Provides secure API key generation, SHA-256 key hashing, storage,
revocation, and validation for Sentinel API endpoints.

Security:
  - Raw API keys are generated using `secrets.token_urlsafe(32)` with prefix `sk_sentinel_`.
  - Raw keys are NEVER stored on disk or logged — only SHA-256 hashes are persisted.
  - Full raw key is returned ONLY ONCE upon initial generation.
  - Subsequential queries return masked key strings (e.g., `sk_sentinel_...a4f1`).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .config import CONFIG

KEY_STORAGE_FILE = Path(CONFIG.ledger_path).parent / "api_keys.json"


def _hash_key(raw_key: str) -> str:
    """Compute SHA-256 hash of a raw API key."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def _mask_key(raw_key: str) -> str:
    """Return a privacy-masked representation of an API key."""
    if len(raw_key) <= 18:
        return "sk_sentinel_***"
    return f"{raw_key[:14]}...{raw_key[-4:]}"


class APIKeyManager:
    def __init__(self, storage_path: Path | None = None) -> None:
        self.path = storage_path or KEY_STORAGE_FILE
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"keys": []}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"keys": []}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def generate_key(self) -> Tuple[str, Dict[str, Any]]:
        """Generate a new secure API key, revoking any prior active keys.

        Returns:
            Tuple of (raw_api_key, key_record_dict)
            Note: raw_api_key MUST be presented to user immediately as it is not stored.
        """
        # Revoke existing active keys
        now_iso = datetime.now(timezone.utc).isoformat()
        for k in self.data.get("keys", []):
            if k.get("status") == "active":
                k["status"] = "revoked"
                k["revoked_at"] = now_iso

        # Generate secure random key
        token = secrets.token_urlsafe(32)
        raw_key = f"sk_sentinel_{token}"
        key_hash = _hash_key(raw_key)
        masked = _mask_key(raw_key)

        record = {
            "id": f"key_{len(self.data.get('keys', [])) + 1}",
            "key_hash": key_hash,
            "masked": masked,
            "status": "active",
            "created_at": now_iso,
            "revoked_at": None,
        }

        self.data.setdefault("keys", []).append(record)
        self._save()
        return raw_key, record

    def revoke_key(self) -> bool:
        """Revoke the current active API key."""
        now_iso = datetime.now(timezone.utc).isoformat()
        revoked_any = False
        for k in self.data.get("keys", []):
            if k.get("status") == "active":
                k["status"] = "revoked"
                k["revoked_at"] = now_iso
                revoked_any = True
        if revoked_any:
            self._save()
        return revoked_any

    def validate_key(self, raw_key: str | None) -> bool:
        """Validate if a raw API key or session token is authorized."""
        keys = self.data.get("keys", [])

        # Unconfigured state (no keys ever created) -> open access out-of-the-box
        if not keys:
            return True

        if not raw_key or not isinstance(raw_key, str):
            return False

        token = raw_key.strip()
        if token.startswith("sk_session_"):
            from .email_activation import activation_manager
            return activation_manager.validate_session_token(token)

        active_keys = [k for k in keys if k.get("status") == "active"]
        if not active_keys:
            return False

        input_hash = _hash_key(token)
        for k in active_keys:
            if secrets.compare_digest(k["key_hash"], input_hash):
                return True
        return False



    def get_status(self) -> Dict[str, Any]:
        """Get summary status of API key configuration."""
        keys = self.data.get("keys", [])
        if not keys:
            return {
                "has_key": False,
                "status": "unconfigured",
                "message": "No API key generated yet. System is operating in open local mode.",
                "masked": None,
                "created_at": None,
            }

        latest = keys[-1]
        active = [k for k in keys if k.get("status") == "active"]

        if active:
            curr = active[-1]
            return {
                "has_key": True,
                "status": "active",
                "message": "API Key is Active.",
                "masked": curr["masked"],
                "created_at": curr["created_at"],
            }

        return {
            "has_key": True,
            "status": "revoked",
            "message": "API Key is Revoked. API requests require generating a new key.",
            "masked": latest["masked"],
            "created_at": latest["created_at"],
            "revoked_at": latest.get("revoked_at"),
        }


# Global singleton instance
auth_manager = APIKeyManager()
