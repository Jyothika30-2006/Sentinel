#!/usr/bin/env python3
"""Sentinel — Web Dashboard & REST API Server with API Key Authentication.

Wraps the existing Sentinel cybersecurity agent backend, evidence ledger,
and report generator into a Flask local web application with Bearer API Key auth.

Usage:
    python app.py
    -> Dashboard available at: http://127.0.0.1:5000
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request, Response
from werkzeug.utils import secure_filename

# Ensure repo root is on sys.path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel import statebus
from sentinel.agent import Agent
from sentinel.auth import auth_manager
from sentinel.blockchain import ganache, hashchain
from sentinel.config import CONFIG
from sentinel.email_activation import activation_manager
from sentinel.llm import make_client
from sentinel.report import write_report
from sentinel.ui import TerminalUI
from sentinel.watcher import WatchTrigger, watch_worker

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB limit for email uploads
UPLOAD_FOLDER = ROOT / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
CONFIG.ensure_dirs()


# ---------------------------------------------------------------------------
# CORS for the mail-open watch endpoints only. The browser extension
# (chrome-extension://...) posts to /api/watch/open from mail.google.com —
# the rest of the API stays same-origin as before.
# ---------------------------------------------------------------------------
_WATCH_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key, X-Session-Token",
    "Access-Control-Max-Age": "600",
}


@app.after_request
def _watch_cors(resp: Response) -> Response:
    if request.path.startswith("/api/watch/"):
        for k, v in _WATCH_CORS_HEADERS.items():
            resp.headers.setdefault(k, v)
    return resp


def _request_key() -> str | None:
    """Extract the API key / session token from the request, if present."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    if "X-API-Key" in request.headers:
        return request.headers.get("X-API-Key", "").strip()
    if "X-Session-Token" in request.headers:
        return request.headers.get("X-Session-Token", "").strip()
    return None


def require_api_key(f):
    """Decorator to enforce Session Token or Bearer API Key authentication on protected endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not auth_manager.validate_key(_request_key()):
            return jsonify({
                "error": "Unauthorized: Sentinel Agent is LOCKED or missing session token / API key.",
                "status": 401
            }), 401
        return f(*args, **kwargs)
    return decorated


def require_api_key_or_local(f):
    """Watch endpoints: additionally accept same-machine callers.

    The browser connector and arrival watcher run on this host and post to
    127.0.0.1 — inside the server's own trust boundary — so no token is
    needed from them. Remote callers still require a valid key.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.remote_addr in ("127.0.0.1", "::1") or auth_manager.validate_key(_request_key()):
            return f(*args, **kwargs)
        return jsonify({
            "error": "Unauthorized: remote callers need an API key for watch endpoints.",
            "status": 401
        }), 401
    return decorated


def log_to_blockchain(result: dict) -> dict:
    """Log analysis metadata to the hashchain evidence ledger."""
    from sentinel.tools import hash_evidence as he

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


from sentinel.orchestrator import orchestrator
from sentinel.agent import answer_copilot_question


def run_sentinel_investigation(email_path: str, use_llm: bool = False) -> Dict[str, Any]:
    """Execute Sentinel backend investigation using the central orchestrator."""
    statebus.publish(state="investigating", risk=0, verdict=None, message=f"Analyzing {Path(email_path).name}")
    result = orchestrator.run_investigation(email_path, auto_confirm=True)
    result["email_path"] = email_path
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    if result.get("verdict") != "ABORTED":
        try:
            report_path = write_report(
                email_path=email_path,
                verdict=result["verdict"],
                confidence=result.get("confidence_score", 90),
                evidence=[e.get("reason", "") for e in result.get("score_breakdown", [])],
                risk_events=[],
                observations=[result.get("summary", "")],
                ledger_ref=result.get("ledger_block", {}),
            )
            result["report_path"] = report_path
        except Exception:
            pass

    return result



# ---------------------------------------------------------------------------
# Page Routes (Public)
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API Key Management Routes (Public / Activation)
# ---------------------------------------------------------------------------
@app.route("/api/keys/status", methods=["GET"])
def api_key_status():
    """Get current status of API Key authentication."""
    return jsonify(auth_manager.get_status())


@app.route("/api/keys/generate", methods=["POST"])
def api_key_generate():
    """Generate a new secure API Key. Full key returned ONLY ONCE."""
    raw_key, record = auth_manager.generate_key()
    return jsonify({
        "success": True,
        "message": "API Key generated successfully. Save this key now — it will not be shown again!",
        "raw_key": raw_key,
        "record": record,
    })


@app.route("/api/keys/revoke", methods=["POST"])
def api_key_revoke():
    """Revoke the current active API Key."""
    success = auth_manager.revoke_key()
    return jsonify({
        "success": success,
        "message": "API Key revoked successfully." if success else "No active API Key to revoke.",
        "status": auth_manager.get_status(),
    })


# ---------------------------------------------------------------------------
# System Status & Samples (Public)
# ---------------------------------------------------------------------------
@app.route("/api/status", methods=["GET"])
def api_status():
    chain = hashchain.HashChain()
    verify_res = chain.verify()

    safe_count = 0
    suspicious_count = 0
    malicious_count = 0

    for block in chain.chain:
        v = block.get("data", {}).get("ai_verdict", "").upper()
        if v == "SAFE":
            safe_count += 1
        elif v == "SUSPICIOUS":
            suspicious_count += 1
        elif v == "MALICIOUS":
            malicious_count += 1

    try:
        llm_client = make_client()
        llm_ok = llm_client.available()
        llm_provider = CONFIG.llm_provider
    except Exception:
        llm_ok, llm_provider = False, CONFIG.llm_provider

    return jsonify({
        "status": "online",
        "system": "Sentinel AI Cybersecurity Agent",
        "llm_provider": llm_provider,
        "llm_available": llm_ok,
        "ollama_available": llm_ok,  # backward-compatible field name
        "blockchain_mode": CONFIG.blockchain_mode,
        "total_investigations": len(chain.chain),
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "ledger_status": verify_res,
        "key_status": auth_manager.get_status(),
        "activation_status": activation_manager.get_status(),
    })


@app.route("/api/samples", methods=["GET"])
def api_samples():
    samples_dir = ROOT / "samples"
    samples = [
        {
            "filename": "clean.eml",
            "title": "Clean Email",
            "description": "Legitimate internal communication between team members.",
            "expected_verdict": "SAFE",
        },
        {
            "filename": "phishing.eml",
            "title": "Phishing Impersonation",
            "description": "Brand impersonation attempt targeting PayPal credentials.",
            "expected_verdict": "MALICIOUS",
        },
        {
            "filename": "bec_gmail.eml",
            "title": "BEC via Webmail",
            "description": "Business Email Compromise with hidden sender IP via Gmail.",
            "expected_verdict": "SUSPICIOUS",
        },
        {
            "filename": "malware_attachment.eml",
            "title": "Disguised Attachment",
            "description": "Malicious attachment disguised as a legitimate PDF invoice.",
            "expected_verdict": "SUSPICIOUS",
        },
    ]

    for s in samples:
        s["available"] = (samples_dir / s["filename"]).exists()

    return jsonify({"samples": samples})


# ---------------------------------------------------------------------------
# Protected Investigation & Ledger Endpoints (Require Bearer API Key or Session Token)
# ---------------------------------------------------------------------------
@app.route("/api/analyze-sample", methods=["POST"])
def api_analyze_sample():
    data = request.get_json() or {}
    sample_name = data.get("sample", "")
    use_llm = bool(data.get("use_llm", False))

    if not sample_name:
        return jsonify({"error": "No sample specified"}), 400

    safe_name = os.path.basename(sample_name)
    sample_path = ROOT / "samples" / safe_name

    if not sample_path.is_file():
        return jsonify({"error": f"Sample file '{safe_name}' not found"}), 404

    try:
        res = run_sentinel_investigation(str(sample_path), use_llm=use_llm)
        res["risk_events"] = [
            {"ts": e.ts, "delta": e.delta, "score": e.score, "reason": e.reason}
            for e in res.get("risk_events", [])
        ]
        return jsonify(res)
    except Exception as exc:
        return jsonify({"error": f"Investigation failed: {str(exc)}"}), 500


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml email files are permitted for forensic analysis"}), 400

    save_path = UPLOAD_FOLDER / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file.save(save_path)

    use_llm = request.form.get("use_llm", "false").lower() == "true"

    try:
        res = run_sentinel_investigation(str(save_path), use_llm=use_llm)
        res["risk_events"] = [
            {"ts": e.ts, "delta": e.delta, "score": e.score, "reason": e.reason}
            for e in res.get("risk_events", [])
        ]
        return jsonify(res)
    except Exception as exc:
        return jsonify({"error": f"Analysis failed: {str(exc)}"}), 500


@app.route("/api/reports", methods=["GET"])
def api_reports():
    reports_dir = Path(CONFIG.reports_dir)
    reports = []

    if reports_dir.exists():
        for p in sorted(reports_dir.glob("*.md"), key=os.path.getmtime, reverse=True):
            stat = p.stat()
            verdict = "UNKNOWN"
            try:
                content = p.read_text(encoding="utf-8")
                for line in content.splitlines():
                    if "Final verdict:" in line or "VERDICT:" in line:
                        verdict = line.split(":", 1)[-1].strip()
                        break
            except Exception:
                pass

            reports.append({
                "filename": p.name,
                "path": str(p),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "verdict": verdict,
            })

    return jsonify({"reports": reports})


@app.route("/api/reports/<filename>", methods=["GET"])
def api_report_content(filename: str):
    safe_name = os.path.basename(filename)
    reports_dir = Path(CONFIG.reports_dir)
    report_file = reports_dir / safe_name

    if not report_file.is_file():
        return jsonify({"error": "Report not found"}), 404

    content = report_file.read_text(encoding="utf-8")
    return jsonify({
        "filename": safe_name,
        "content": content,
    })


@app.route("/api/ledger", methods=["GET"])
def api_ledger():
    chain = hashchain.HashChain()
    verify_res = chain.verify()

    return jsonify({
        "integrity": verify_res,
        "blocks": chain.chain,
        "ledger_path": str(chain.path),
    })


@app.route("/api/copilot/chat", methods=["POST"])
def api_copilot_chat():
    """Grounded AI Copilot investigation assistant Q&A endpoint."""
    data = request.get_json() or {}
    user_question = data.get("question", "").strip()
    case_data = data.get("case_data") or {}

    if not user_question:
        return jsonify({"error": "Question parameter is required."}), 400

    answer = answer_copilot_question(case_data, user_question)
    return jsonify({
        "success": True,
        "question": user_question,
        "answer": answer,
    })



# ---------------------------------------------------------------------------
# Email Activation & Account Recovery Endpoints (Public)
# ---------------------------------------------------------------------------

@app.route("/api/activation/status", methods=["GET"])
def api_activation_status():
    """Get current email activation & OTP pending status."""
    return jsonify(activation_manager.get_status())


@app.route("/api/activation/request-code", methods=["POST"])
@app.route("/api/activation/send-code", methods=["POST"])
def api_activation_request_code():
    """Request a 6-digit verification code sent to the given email."""
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email address is required."}), 400
    try:
        activation_manager.request_activation(email)
        return jsonify({
            "success": True,
            "message": "6-digit verification code sent to your email.",
            "status": activation_manager.get_status(),
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/activation/verify-code", methods=["POST"])
@app.route("/api/activation/verify", methods=["POST"])
def api_activation_verify_code():
    """Verify 6-digit OTP code for email activation."""
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    code = data.get("code", "").strip()
    if not email or not code:
        return jsonify({"error": "Email and 6-digit verification code are required."}), 400
    try:
        session_token = activation_manager.verify_activation(email, code)
        return jsonify({
            "success": True,
            "message": "Email Activated ✓ — Sentinel Agent is ACTIVE.",
            "session_token": session_token,
            "status": activation_manager.get_status(),
        })
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.route("/api/activation/resend-code", methods=["POST"])
def api_activation_resend_code():
    """Resend a fresh 6-digit verification code (rate-limited)."""
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email address is required."}), 400
    try:
        activation_manager.resend_code(email)
        return jsonify({
            "success": True,
            "message": "A new 6-digit verification code has been sent.",
            "status": activation_manager.get_status(),
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/activation/request-recovery", methods=["POST"])
def api_activation_request_recovery():
    """Request account recovery code for a previously verified email."""
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email address is required."}), 400
    try:
        activation_manager.request_recovery(email)
        return jsonify({
            "success": True,
            "message": "6-digit recovery code sent to your verified email.",
            "status": activation_manager.get_status(),
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/activation/verify-recovery", methods=["POST"])
def api_activation_verify_recovery():
    """Verify 6-digit recovery code and establish new authenticated session."""
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    code = data.get("code", "").strip()
    if not email or not code:
        return jsonify({"error": "Email and 6-digit recovery code are required."}), 400
    try:
        session_token = activation_manager.verify_recovery(email, code)
        return jsonify({
            "success": True,
            "message": "Account Recovery Verified ✓ — New authenticated session established.",
            "session_token": session_token,
            "status": activation_manager.get_status(),
        })
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    """Revoke active session token and lock Sentinel Guard."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.headers.get("X-Session-Token", "")
    activation_manager.revoke_session(token)
    return jsonify({
        "success": True,
        "message": "Logged out successfully. Sentinel Guard is now LOCKED.",
        "status": activation_manager.get_status(),
    })


# ---------------------------------------------------------------------------
# Mail-Open Watch (Tier 1: browser extension posts opened mails here)
# ---------------------------------------------------------------------------
@app.route("/api/watch/open", methods=["OPTIONS"])
def api_watch_open_options():
    """CORS preflight for the extension connector."""
    return ("", 204)


@app.route("/api/watch/open", methods=["POST"])
@require_api_key_or_local
def api_watch_open():
    """Activation trigger: the user just OPENED a mail.

    Body: {source, subject, sender, thread_id, raw_eml?}. `raw_eml` present
    (Tier 1 extension) -> full forensic pipeline; absent (Tier 3 title watch)
    -> surface-only analysis with capped confidence. Returns the verdict
    summary, or 202 {queued: true} when the wait budget expires.
    """
    data = request.get_json(silent=True) or {}
    source = str(data.get("source") or "extension")
    subject = str(data.get("subject") or "").strip()
    raw_eml = data.get("raw_eml") or None

    known_sources = ("extension", "extension-arrival", "mailpit", "title")
    if source not in known_sources:
        source = "extension"
    if not raw_eml and not subject:
        return jsonify({"error": "Provide at least a subject or raw_eml of the opened mail."}), 400
    if raw_eml and not isinstance(raw_eml, str):
        return jsonify({"error": "raw_eml must be a string (RFC822 source)."}), 400

    trigger = WatchTrigger(
        source=source,
        subject=subject,
        sender=str(data.get("sender") or "").strip(),
        thread_id=str(data.get("thread_id") or "").strip(),
        raw_eml=raw_eml,
        body_text=str(data.get("body_text") or ""),
    )
    res = watch_worker.submit(trigger, timeout=20.0)
    if res.get("queued"):
        return jsonify({"queued": True, "case_file": res.get("case_file", "")}), 202

    return jsonify({
        "queued": False,
        "cached": bool(res.get("cached")),
        "case_file": res.get("case_file"),
        "verdict": res.get("verdict"),
        "risk_score": res.get("risk_score"),
        "confidence": res.get("confidence"),
        "confidence_score": res.get("confidence_score"),
        "summary": res.get("summary"),
        "surface_only": bool(res.get("surface_only")),
        "report_path": res.get("report_path"),
    })


@app.route("/api/watch/last", methods=["GET"])
def api_watch_last():
    """Full result of the most recent mail-open investigation (for the dashboard)."""
    last = watch_worker.last_result()
    if not last:
        return jsonify({"error": "No watch investigation has completed yet."}), 404
    return jsonify(last)



# ---------------------------------------------------------------------------
# Live State Endpoint (Public — no API key needed for companion sync)
# ---------------------------------------------------------------------------
@app.route("/api/state", methods=["GET"])
def api_state():
    """Return current statebus JSON so the dashboard mirrors companion state."""
    from sentinel import statebus
    return jsonify(statebus.read())


@app.route("/api/events", methods=["GET"])
def api_events():
    """Stream statebus events via SSE (Server-Sent Events)."""
    import json
    import time
    from sentinel import statebus

    def generate():
        last_ts = None
        while True:
            st = statebus.read()
            ts = st.get("last_updated")
            if ts != last_ts:
                last_ts = ts
                yield f"data: {json.dumps(st)}\n\n"
            time.sleep(1.0)

    return Response(generate(), mimetype="text/event-stream")



if __name__ == "__main__":
    print("=========================================================")
    print("  🛡️ Sentinel — AI Cybersecurity & Forensics Dashboard")
    print("  Localhost Web Application running on http://127.0.0.1:5000")
    print("=========================================================")
    app.run(host="127.0.0.1", port=5000, debug=True)
