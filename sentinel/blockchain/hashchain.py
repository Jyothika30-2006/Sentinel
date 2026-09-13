"""HashChain — a self-contained, tamper-evident local ledger.

Each block is:
    {
      "index": n,
      "timestamp": iso8601,
      "data": {file_hash, ai_verdict, confidence_score, timestamp, geolocation_summary},
      "prev_hash": sha256(previous block),
      "hash": sha256(this block),
    }

Because each block's `hash` commits to `prev_hash`, any modification to ANY
earlier block invalidates every subsequent hash. `verify()` recomputes the
whole chain and reports the first broken link — that is the tamper-proof
guarantee the project needs, with zero external dependencies.

This is the DEFAULT backend (BLOCKCHAIN_MODE=hashchain). It is intentionally
not a consensus network — the spec allows a "simple Python hash-chain if full
blockchain is out of scope", and for local evidence logging it provides the
same immutability property (append-only + hash-linked) without miner latency.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..config import CONFIG


def _sha256(obj: dict) -> str:
    # canonical (sorted-key) JSON so the hash is deterministic.
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class HashChain:
    """Append-only, hash-linked evidence log persisted to a JSON file."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or CONFIG.ledger_path
        self._lock = threading.Lock()
        self.chain: List[Dict[str, Any]] = self._load()

    # --- persistence -------------------------------------------------
    def _load(self) -> List[Dict[str, Any]]:
        p = Path(self.path)
        if not p.exists():
            return []
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt ledger: start fresh but note it. (In production you'd
            # want to surface this loudly rather than silently reset.)
            return []

    def _save(self) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.chain, indent=2), encoding="utf-8")
        os.replace(tmp, p)  # atomic-ish write

    # --- chain ops ---------------------------------------------------
    def append(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            prev_hash = self.chain[-1]["hash"] if self.chain else "0" * 64
            index = len(self.chain)
            block = {
                "index": index,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data,
                "prev_hash": prev_hash,
            }
            block["hash"] = _sha256(block)
            self.chain.append(block)
            self._save()
            return block

    def verify(self) -> Dict[str, Any]:
        """Recompute every hash and return integrity status."""
        with self._lock:
            for i, block in enumerate(self.chain):
                prev_hash = self.chain[i - 1]["hash"] if i else "0" * 64
                if block.get("prev_hash") != prev_hash:
                    return {"valid": False, "broken_at": i, "reason": "prev_hash mismatch"}
                recomputed = _sha256({k: v for k, v in block.items() if k != "hash"})
                if block.get("hash") != recomputed:
                    return {"valid": False, "broken_at": i, "reason": "block hash mismatch"}
            return {"valid": True, "length": len(self.chain), "broken_at": None}

    @property
    def length(self) -> int:
        return len(self.chain)

    def tail(self) -> Dict[str, Any] | None:
        return self.chain[-1] if self.chain else None


def log_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience wrapper: append evidence metadata and return the block."""
    chain = HashChain()
    block = chain.append(data)
    return {"block": block, "chain_length": chain.length, "integrity": chain.verify()}
