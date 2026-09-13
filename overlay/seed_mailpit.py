#!/usr/bin/env python3
"""Seed a running Mailpit instance with the sample emails for demo/testing.

Mailpit captures SMTP mail on port 1025. This script re-sends samples/*.eml
through a local SMTP session so the Sentinel pet's mail panel has something
to display without a real Gmail account.

Run after starting Mailpit:
    docker run -d -p 8025:8025 -p 1025:1025 axllent/mailpit
    python -m overlay.seed_mailpit            # sends all samples/*.eml
    python -m overlay.seed_mailpit samples/phishing.eml
"""
from __future__ import annotations

import smtplib
import sys
from email import message_from_binary_file
from pathlib import Path

HOST, PORT = "localhost", 1025


def send_eml(path: Path) -> None:
    msg = message_from_binary_file(open(path, "rb"))
    to_addrs = msg.get_all("To", []) or ["demo@local.test"]
    from_addr = msg.get("From", "demo@local.test")
    with smtplib.SMTP(HOST, PORT) as smtp:
        smtp.sendmail(from_addr, to_addrs, msg.as_bytes())
    print(f"  sent {path.name} -> {to_addrs}")


def main() -> int:
    paths = [Path(a) for a in sys.argv[1:]] or sorted(Path("samples").glob("*.eml"))
    if not paths:
        print("no .eml files found")
        return 1
    print(f"Seeding Mailpit at {HOST}:{PORT} ...")
    for p in paths:
        try:
            send_eml(p)
        except Exception as exc:
            print(f"  FAILED {p.name}: {exc}")
    print("Done. Open http://localhost:8025 or run the pet with --mail mailpit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
