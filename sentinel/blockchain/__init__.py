"""Blockchain evidence-logging layer.

Two interchangeable backends share one interface:

  * hashchain.HashChain  — pure-Python tamper-evident hash chain (default).
  * ganache.EthLogger    — writes metadata to a local Ganache/Ethereum
                           testnet via web3 (optional, heavier).

Only {file_hash, verdict, confidence, timestamp, geolocation_summary} is
logged — NEVER the raw email/attachment. This is evidence integrity, not a
storage layer, so it stays fast and cheap.
"""
from . import hashchain  # noqa: F401
