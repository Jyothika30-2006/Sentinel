"""ganache — optional Ethereum-testnet backend (BLOCKCHAIN_MODE=ganache).

Logs the same metadata (hash + verdict + confidence + timestamp + geo
summary) as a transaction to a local Ganache node via web3. Used only when
a full blockchain demo is desired; otherwise hashchain is the default.

The data is written to a tiny key/value `EvidenceLog` contract (or, for a
pure demo without Solidity compilation, as a raw value-transfer transaction
carrying the JSON in its input `data` field — no contract needed).

NOTE: this is OPTIONAL. web3 + a running Ganache node are required; if
either is missing, callers should fall back to HashChain.
"""
from __future__ import annotations

from typing import Any, Dict

from ..config import CONFIG


class EthLogger:
    def __init__(self) -> None:
        self.rpc = CONFIG.ganache_rpc_url
        self.account = CONFIG.ganache_account

    def _web3(self):
        try:
            from web3 import Web3  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("web3 not installed (pip install web3)") from e
        w3 = Web3(Web3.HTTPProvider(self.rpc))
        if not w3.is_connected():
            raise RuntimeError(f"cannot connect to Ganache at {self.rpc}")
        return w3

    def log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        import json

        w3 = self._web3()
        payload = w3.to_hex(text=json.dumps(data, sort_keys=True))
        tx = {
            "from": self.account,
            "to": self.account,  # self-transfer; data field carries the JSON
            "value": 0,
            "data": payload,
        }
        tx_hash = w3.eth.send_transaction(tx)
        return {"tx_hash": tx_hash.hex(), "rpc": self.rpc, "data": data}


def log_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    """Log to Ganache; fall back to hashchain on any failure."""
    try:
        return EthLogger().log(data)
    except Exception as exc:
        from . import hashchain

        block = hashchain.log_evidence(data)
        block["ganache_error"] = str(exc)
        return block
