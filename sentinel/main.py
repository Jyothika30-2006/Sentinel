"""Command-line entry point: parse args, wire up the agent, run, and log
evidence + write the report. Also registers the sandbox teardown on kill-switch.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import Agent
from .blockchain import hashchain, ganache
from .config import CONFIG
from .killswitch import KILLSWITCH, TERMINAL
from .report import write_report
from .ui import TerminalUI, render_verdict_panel


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="AI-Powered Cybersecurity Agent for Email Threat Detection & Forensics",
    )
    p.add_argument("email", nargs="?", help="path to the .eml file to investigate (required unless --verify-chain)")
    p.add_argument("--no-llm", action="store_true", help="run deterministic pipeline (no Ollama)")
    p.add_argument("--no-sandbox", action="store_true", help="disable Docker sandbox (static-only host fallback)")
    p.add_argument("--mode", choices=["agent", "chain"], default="agent",
                   help="agent = full investigation; chain = verify blockchain ledger only")
    p.add_argument("--verify-chain", action="store_true", help="verify hash-chain integrity and exit")
    return p.parse_args(argv)


def log_to_blockchain(result: dict) -> dict:
    """Write verdict metadata to the configured backend (never raw email)."""
    from .tools import hash_evidence as he

    # The email hash is the anchor; if absent, compute it quickly.
    try:
        email_hash = he.hash_evidence(result["email_path"])["email_sha256"]
    except Exception:
        email_hash = "unavailable"

    data = {
        "file_hash": email_hash,
        "ai_verdict": result["verdict"],
        "confidence_score": result["confidence"],
        "timestamp": result.get("timestamp", ""),
        "geolocation_summary": result.get("geolocation_summary", "n/a"),
    }
    if CONFIG.blockchain_mode == "ganache":
        return ganache.log_evidence(data)
    return hashchain.log_evidence(data)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    CONFIG.ensure_dirs()

    # --- chain verification shortcut ---------------------------------
    if args.verify_chain or args.mode == "chain":
        chain = hashchain.HashChain()
        status = chain.verify()
        ui = TerminalUI()
        ui.console.print(f"Ledger: {chain.path} -> {status}")
        return 0 if status["valid"] else 1

    # --- normal investigation ----------------------------------------
    if not args.email:
        print("[!] provide an .eml path to investigate (or use --verify-chain).")
        return 2
    email_path = str(Path(args.email).resolve())
    if not Path(email_path).is_file():
        print(f"[!] email file not found: {args.email}")
        return 2

    if args.no_sandbox:
        CONFIG.sandbox_enabled = False

    ui = TerminalUI()
    ui.start(email_path)

    agent = Agent(ui, email_path, use_llm=not args.no_llm)

    # Start the shared terminal input (keypress kill-switch + confirmation)
    # BEFORE running the investigation.
    TERMINAL.start()

    try:
        result = agent.run()
    except KeyboardInterrupt:
        KILLSWITCH.abort("Ctrl+C")
        result = {"verdict": "ABORTED", "confidence": 0, "risk_score": agent.risk.score,
                  "evidence": [e.reason for e in agent.risk.events], "observations": agent.observations,
                  "risk_events": agent.risk.events}
    finally:
        TERMINAL.stop()

    ui.stop()

    # --- finalize ----------------------------------------------------
    from datetime import datetime, timezone

    result["email_path"] = email_path
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    if result["verdict"] != "ABORTED":
        # Blockchain evidence log (metadata only).
        try:
            ledger_ref = log_to_blockchain(result)
        except Exception as exc:
            ledger_ref = {"error": str(exc)}
        result["ledger_ref"] = ledger_ref

        # Forensic report.
        report_path = write_report(
            email_path=email_path,
            verdict=result["verdict"],
            confidence=result["confidence"],
            evidence=result.get("evidence", []),
            risk_events=result.get("risk_events", []),
            observations=result.get("observations", []),
            ledger_ref=ledger_ref,
        )
        result["report_path"] = report_path

    # Final render (non-live).
    render_verdict_panel(
        result["verdict"], result["confidence"],
        result.get("evidence", []), result.get("risk_score", 0),
    )
    if "report_path" in result:
        ui.console.print(f"[dim]Report saved: {result['report_path']}[/]")
    if "ledger_ref" in result:
        ui.console.print(f"[dim]Blockchain ledger: {CONFIG.ledger_path} (length {result['ledger_ref'].get('chain_length', '?')})[/]")

    return 0
