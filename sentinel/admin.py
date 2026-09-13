"""Sentinel Administrative CLI Utility.

Allows administrators to inspect, manage, and reset Sentinel Guard activation,
recovery state, and session tokens directly via local terminal CLI.

Usage:
    python -m sentinel.admin status
    python -m sentinel.admin reset
    python -m sentinel.admin activate <email>
"""
from __future__ import annotations

import sys
from pathlib import Path

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from sentinel.email_activation import activation_manager


def print_banner():
    print("=" * 60)
    print("  🛡️ SENTINEL GUARD — Administrative Management Utility")
    print("=" * 60)


def show_status():
    print_banner()
    st = activation_manager.get_status()
    print(f"Current State:      {st.get('state')}")
    print(f"Is Activated:       {st.get('activated')}")
    print(f"Verified Email:     {st.get('email') or 'None'}")
    print(f"Activated At:       {st.get('activated_at') or 'n/a'}")
    print(f"Active Session:     {'Yes' if st.get('session_active') else 'No'}")
    print("-" * 60)


def reset_activation():
    print_banner()
    activation_manager.deactivate()
    print("[✓] Sentinel activation state reset to LOCKED.")
    print("[✓] All active session tokens revoked.")
    print("-" * 60)


def force_activate(email: str):
    print_banner()
    token = activation_manager.admin_force_activate(email)
    print(f"[✓] Admin Force Activated: {email}")
    print(f"[✓] Session Token Issued:  {token}")
    print("-" * 60)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("Usage: python -m sentinel.admin [status|reset|activate <email>]")
        return 0

    cmd = args[0].lower()
    if cmd == "status":
        show_status()
    elif cmd == "reset":
        reset_activation()
    elif cmd == "activate":
        if len(args) < 2:
            print("Error: Email address required. Usage: python -m sentinel.admin activate user@example.com")
            return 1
        force_activate(args[1])
    else:
        print(f"Unknown command '{cmd}'. Available commands: status, reset, activate <email>")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
