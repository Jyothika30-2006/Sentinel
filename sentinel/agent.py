"""Agent controller — the THINK → CHOOSE TOOL → ACT → OBSERVE loop.

This is the reasoning brain wrapper. It:

  1. Holds the conversation with the local LLM (or runs deterministically
     if the LLM is offline / --no-llm).
  2. Enforces the TOOL WHITELIST — every tool call goes through registry
     lookup; there is NO shell exec and NO dynamic import.
  3. Applies the SAFETY GATES before execution:
        - confirmation gate ([CONFIRM_NEEDED] / requires_confirmation),
        - kill-switch check before AND after every step,
        - hard per-tool timeout,
        - sandbox routing for file_touching tools.
  4. Maintains the running risk score via RiskTracker.
  5. Streams everything to the TerminalUI.

The LLM only ever *selects* tools by name; the controller is the only thing
that maps a name to code and actually runs it.
"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Any, Dict, List, Optional

from .config import CONFIG
from .killswitch import KILLSWITCH, TERMINAL
from .llm import make_client
from .prompt import build_messages
from .risk import RiskTracker
from .tools import registry
from .ui import TerminalUI
from . import statebus

MAX_ITERATIONS = 20  # hard cap on agent steps (safety: bounded loop)


class Agent:
    def __init__(self, ui: TerminalUI, email_path: str, use_llm: bool = True,
                 auto_confirm: bool = False) -> None:
        self.ui = ui
        self.email_path = email_path
        self.risk = RiskTracker()
        self.observations: List[str] = []
        self.llm = None
        self.messages: List[Dict[str, Any]] = []
        self._use_llm = use_llm and self._init_llm()
        self._confirmed_tools: set = set()  # tools already approved this session
        self._auto_confirm = auto_confirm  # GUI-triggered: skip the human prompt
        self.geo_summary: str = "n/a"       # captured for the blockchain record

    # ------------------------------------------------------------------
    def _init_llm(self) -> bool:
        try:
            client = make_client()
        except ValueError as exc:  # provider configured but missing settings
            self.ui.log(f"[yellow]LLM provider misconfigured ({exc}) — deterministic mode.[/]")
            return False
        if client.available():
            self.llm = client
            return True
        self.ui.log("[yellow]LLM provider not reachable — running in deterministic (no-LLM) mode.[/]")
        return False

    # ------------------------------------------------------------------
    # Safety: confirmation gate
    # ------------------------------------------------------------------
    def _request_confirmation(self, tool_name: str, args: Dict) -> bool:
        """Blocking human approval before a file-touching tool runs.

        If auto_confirm is set (GUI-triggered analysis), approval is implicit
        because the user already clicked "Analyze" — but we still log it.
        """
        if self._auto_confirm:
            self._confirmed_tools.add(tool_name)
            return True
        self.ui.log(f"[bold red][CONFIRM_NEEDED][/] tool `{tool_name}` will touch files inside the sandbox.")
        self.ui.log(f"[dim]    args: {json.dumps(args, default=str)}[/]")
        answer = TERMINAL.prompt("    Type 'yes' to approve, anything else to deny: ").strip().lower()
        if answer == "yes":
            self._confirmed_tools.add(tool_name)
            self.ui.log("[green]    approved.[/]")
            return True
        self.ui.log("[yellow]    denied — skipping tool.[/]")
        return False

    # ------------------------------------------------------------------
    # Safety: bounded tool execution with timeout + kill-switch
    # ------------------------------------------------------------------
    def _execute_tool(self, name: str, args: Dict) -> Dict:
        tool = registry.get(name)
        if tool is None:
            # Whitelist violation — the agent asked for a tool that doesn't exist.
            return {"error": f"tool '{name}' is not in the whitelist; refusing to run"}

        if tool.file_touching and name not in self._confirmed_tools:
            statebus.publish(state="confirm_needed", current_tool=name,
                             message=f"approval needed for {name}")
            if not self._request_confirmation(name, args):
                statebus.publish(state="tool_running", current_tool=name,
                                 message=f"{name} denied by operator")
                return {"skipped": True, "reason": "human denied confirmation"}

        if KILLSWITCH.aborted:
            return {"aborted": True}

        self.ui.tool(name, args)
        statebus.publish(state="tool_running", current_tool=name, message=f"running {name}")
        # Run with a hard timeout in a worker thread so a hung tool can't
        # stall the demo (SAFETY PARAMETER #5).
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(tool.fn, **args)
            try:
                result = fut.result(timeout=CONFIG.tool_timeout_seconds)
            except FutureTimeout:
                return {"error": f"tool timed out after {CONFIG.tool_timeout_seconds}s"}
            except Exception as exc:  # noqa: BLE001 - surface any tool error safely
                return {"error": f"{type(exc).__name__}: {exc}"}
        return result

    # ------------------------------------------------------------------
    # Risk-score synthesis from a tool result
    # ------------------------------------------------------------------
    def _apply_risk(self, name: str, result: Dict) -> None:
        """Map tool results to risk deltas. Conservative, evidence-based."""
        if result.get("aborted") or result.get("skipped"):
            return

        if "error" in result:
            # A failed tool is NOT evidence of malice; do not inflate score.
            self.ui.observation(f"[{name}] error: {result['error']}")
            return

        delta = 0
        reasons = []

        if name == "parse_headers":
            auth = result.get("auth", {})
            spf, dkim = auth.get("spf"), auth.get("dkim")
            if spf == "fail":
                delta += 25
                reasons.append("SPF check failed (sender domain mismatch)")
            elif spf == "softfail":
                delta += 15
                reasons.append("SPF softfail")
            if dkim in ("fail", "none", "neutral"):
                delta += 10
                reasons.append(f"DKIM {dkim} (no valid sender signature)")

        elif name == "extract_urls":
            sus = result.get("suspicious_links", [])
            mm = result.get("brand_mismatches", [])
            # Sum the per-link evidence-weighted risk contribution (capped).
            total = sum(l.get("risk_contribution", 0) for l in sus)
            if mm:
                delta += 25
                reasons.append(f"{len(mm)} brand/domain mismatch(es)")
            if total:
                delta += min(total, 60)
                reasons.append(f"URL risk signals worth {min(total, 60)}pts")

        elif name == "check_tor_exit":
            if result.get("tor_exit"):
                delta += 20
                reasons.append("sender IP is a Tor exit node (origin anonymized)")

        elif name == "check_reputation":
            if result.get("available"):
                for src, r in result["results"].items():
                    if isinstance(r, dict):
                        if src == "virustotal" and r.get("malicious", 0) > 0:
                            delta += 20
                            reasons.append(f"VirusTotal: {r['malicious']} malicious detections")
                        if src == "abuseipdb" and r.get("abuse_confidence_score", 0) >= 50:
                            delta += 15
                            reasons.append(f"AbuseIPDB score {r['abuse_confidence_score']}")

        elif name == "static_file_scan":
            results = result.get("results", {})
            flags = results.get("risk_flags", [])
            if flags:
                delta += 20 + 10 * min(len(flags), 2)
                reasons.append(f"attachment flags: {', '.join(flags)}")
            if results.get("entropy_high"):
                delta += 10

        elif name in ("binwalk_scan", "pdfid_scan", "capa_scan", "strings_scan",
                      "yara_scan", "pecheck_scan"):
            results = result.get("results", {})
            flags = results.get("flags", [])
            if flags:
                delta += 15 + 10 * min(len(flags), 2)
                reasons.append(f"{name}: {', '.join(flags[:3])}")

        elif name == "dns_lookup":
            # Missing SPF/DMARC on a mail-sending domain = weak anti-spoofing.
            if result.get("a") and not result.get("has_spf"):
                delta += 10
                reasons.append("domain has no SPF record")
            if not result.get("has_dmarc"):
                delta += 5
                reasons.append("domain has no DMARC record")

        elif name == "whois_lookup":
            # Very young domain + privacy protection = common throwaway-phish pattern.
            created = result.get("creation_date")
            if created and result.get("privacy_protected"):
                delta += 15
                reasons.append(f"privacy-protected whois, created {created}")

        elif name == "resolve_origin":
            if result.get("confidence", 0) < 0.3 and result.get("method") == "fallback":
                # Unrecoverable origin is neutral, not malicious — but we note it.
                reasons.append("sender origin unrecoverable (webmail relay); confidence lowered")

        elif name == "geolocate_ip":
            loc = result.get("location", {}) or {}
            city, country = loc.get("city"), loc.get("country")
            self.geo_summary = f"{city}, {country}" if city or country else "unresolved"
            # A geolocation failure is NEUTRAL (not evidence of malice), so we
            # do not add a risk delta here — only record the summary.

        if delta or reasons:
            score = self.risk.update(delta, f"{name}: " + ("; ".join(reasons) if reasons else "no change"))
            self.ui.set_risk(score, self.risk.events[-1].reason if self.risk.events else "")

        summary = self._summarize(name, result)
        self.ui.observation(summary)
        self.observations.append(f"[{name}] {summary}")

    def _summarize(self, name: str, result: Dict) -> str:
        """Compact human summary of a tool result for the log."""
        if name == "parse_headers":
            return f"{result.get('received_count', 0)} Received hop(s); from={result.get('From')}"
        if name == "hash_evidence":
            return f"SHA-256={result.get('email_sha256', '?')[:16]}…; {len(result.get('attachments', {}))} attachment(s)"
        if name == "resolve_origin":
            return f"origin={result.get('origin_ip') or 'unrecoverable'} via {result.get('method')} (conf={result.get('confidence', 0):.0%})"
        if name == "geolocate_ip":
            loc = result.get("location", {})
            return f"{result.get('ip')} -> {loc.get('city')}, {loc.get('country')} (conf={result.get('confidence', 0):.0%}, r≈{result.get('radius_km')}km)"
        if name == "check_tor_exit":
            return f"{result.get('ip')}: {'TOR EXIT' if result.get('tor_exit') else 'not Tor'}"
        if name == "extract_urls":
            return f"{result.get('total_links')} link(s), {len(result.get('suspicious_links', []))} suspicious"
        if name == "check_reputation":
            return f"{result.get('target')} ({result.get('kind')}): available={result.get('available')}"
        if name == "static_file_scan":
            return f"sandboxed={result.get('sandboxed')}; {json.dumps(result.get('results', {}).get('risk_flags', []))}"
        return json.dumps(result, default=str)[:120]

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        # Announce to the desktop pet that an investigation has begun.
        statebus.publish(state="investigating", risk=0, verdict=None,
                         current_tool=None, message="investigation started")

        # Pre-load the untrusted email data into the prompt (inside tags).
        email_data = self._load_email_data()

        if self._use_llm and self.llm:
            result = self._run_llm_loop(email_data)
        else:
            result = self._run_deterministic()

        return result

    def _load_email_data(self) -> str:
        """Read the .eml as untrusted text for the LLM (bounded size)."""
        try:
            with open(self.email_path, "rb") as fh:
                raw = fh.read(200_000)  # cap to protect the LLM context
            return raw.decode("utf-8", errors="replace")
        except OSError:
            return f"(could not read email: {self.email_path})"

    def _run_llm_loop(self, email_data: str) -> Dict[str, Any]:
        """LLM tool-calling loop: THINK → CHOOSE TOOL → ACT → OBSERVE."""
        self.messages = build_messages(email_data)
        tools = registry.schemas()

        for _ in range(MAX_ITERATIONS):
            if KILLSWITCH.aborted:
                return self._finalize("ABORTED", 0, "kill-switch pressed")

            try:
                resp = self.llm.chat(self.messages, tools=tools)  # type: ignore[union-attr]
            except Exception as exc:
                self.ui.log(f"[red]LLM error: {exc}[/] — falling back to deterministic pipeline.")
                return self._run_deterministic()

            # Record the assistant message (text + any tool calls) into history.
            assistant_msg = {"role": "assistant", "content": self.llm.extract_text(resp)}  # type: ignore[union-attr]
            tool_calls = self.llm.extract_tool_calls(resp)  # type: ignore[union-attr]

            if assistant_msg["content"]:
                self.ui.reason(assistant_msg["content"])
                statebus.publish(state="thinking", message=assistant_msg["content"][:120])

            if not tool_calls:
                # LLM is done talking; check for a verdict and finish.
                return self._extract_final_verdict(assistant_msg["content"])

            # Attach the tool_calls to the assistant message for Ollama history.
            assistant_msg["tool_calls"] = resp["message"].get("tool_calls", [])
            self.messages.append(assistant_msg)

            for tc in tool_calls:
                name, args = tc["name"], tc.get("arguments", {})
                obs = self._execute_tool(name, args)
                self._apply_risk(name, obs)
                # Feed the observation back as a tool-role message.
                self.messages.append({
                    "role": "tool",
                    "content": json.dumps(obs, default=str),
                })

        # Loop exhausted without a clear verdict.
        return self._finalize("SUSPICIOUS", 50, "iteration cap reached; incomplete analysis")

    def _extract_final_verdict(self, text: str) -> Dict[str, Any]:
        """Parse SAFE/SUSPICIOUS/MALICIOUS + confidence from the LLM's final text."""
        import re

        verdict = "SUSPICIOUS"
        for v in ("MALICIOUS", "SUSPICIOUS", "SAFE"):
            if v in text.upper():
                verdict = v
                break
        m = re.search(r"(\d{1,3})\s*%", text)
        confidence = int(m.group(1)) if m else 50
        confidence = max(0, min(100, confidence))
        return self._finalize(verdict, confidence, text)

    def _run_deterministic(self) -> Dict[str, Any]:
        """Deterministic pipeline (no LLM): same tools, same safety gates."""
        self.ui.reason("Deterministic pipeline (no LLM) — running fixed investigation flow.")

        steps = [
            ("hash_evidence", {"email_path": self.email_path}),
            ("parse_headers", {"email_path": self.email_path}),
        ]
        # Chain: parse headers -> resolve origin -> geolocate -> tor -> urls -> reputation
        parsed = None
        origin = None
        for name, args in steps:
            obs = self._execute_tool(name, args)
            self._apply_risk(name, obs)
            if name == "parse_headers" and "error" not in obs:
                parsed = obs

        if parsed:
            obs = self._execute_tool("resolve_origin", {"headers": parsed})
            self._apply_risk("resolve_origin", obs)
            origin = obs

        if origin and origin.get("origin_ip"):
            obs = self._execute_tool("geolocate_ip", {"ip": origin["origin_ip"]})
            self._apply_risk("geolocate_ip", obs)
            obs = self._execute_tool("check_tor_exit", {"ip": origin["origin_ip"]})
            self._apply_risk("check_tor_exit", obs)

        # URLs from body (need the parsed body; read it directly here).
        from .tools import _emailutil

        body = _emailutil.get_body(_emailutil.parse_email(self.email_path))
        obs = self._execute_tool("extract_urls", {"body": body})
        self._apply_risk("extract_urls", obs)

        # Lightweight BEC/content heuristic (deterministic stand-in for the
        # LLM's writing-style analysis when no LLM is available).
        self._apply_content_heuristics(body)

        if origin and origin.get("origin_ip"):
            obs = self._execute_tool("check_reputation", {"target": origin["origin_ip"], "kind": "ip"})
            self._apply_risk("check_reputation", obs)

        # Attachments -> static_file_scan + forensic binaries (require confirmation).
        msg = _emailutil.parse_email(self.email_path)
        atts = _emailutil.extract_attachments(msg, "evidence/attachments/pending")
        for att in atts:
            obs = self._execute_tool("static_file_scan", {"attachment_path": att})
            self._apply_risk("static_file_scan", obs)
            # Deep forensic pass (binwalk / strings / pdfid-if-pdf).
            for ftool in ("binwalk_scan", "strings_scan", "pdfid_scan"):
                obs = self._execute_tool(ftool, {"attachment_path": att})
                self._apply_risk(ftool, obs)

        # Phishing-infrastructure tracing: DNS + whois on link domains.
        from .tools import extract_urls as _eu

        url_result = _eu.extract_urls(body)
        domains = set()
        for l in url_result.get("suspicious_links", []):
            dom = l.get("domain")
            if dom:
                domains.add(dom)
        for dom in list(domains)[:3]:
            obs = self._execute_tool("dns_lookup", {"domain": dom})
            self._apply_risk("dns_lookup", obs)
            obs = self._execute_tool("whois_lookup", {"domain": dom})
            self._apply_risk("whois_lookup", obs)

        # Verdict from accumulated risk.
        score = self.risk.score
        if score >= 60:
            verdict, conf = "MALICIOUS", score
        elif score >= 30:
            verdict, conf = "SUSPICIOUS", score
        else:
            verdict, conf = "SAFE", max(60, 100 - score)
        return self._finalize(verdict, conf, "deterministic scoring")

    def _apply_content_heuristics(self, body: str) -> None:
        """Deterministic linguistic/social-engineering signals (LLM stand-in).

        These are *weak, low-weight* signals — the same kind of "writing
        style" analysis the LLM performs, but keyword-based. Kept deliberately
        conservative so a legitimate urgent email is not over-scored.
        """
        low = body.lower()
        urgency = any(k in low for k in (
            "urgent", "asap", "immediately", "act now", "24 hour",
            "time-sensitive", "time sensitive", "can't talk", "right now",
            "today", "before monday", "without delay",
        ))
        secrecy = any(k in low for k in ("confidential", "do not discuss", "keep this private", "don't tell anyone"))
        # Word-boundary match so short terms (e.g. "ach") don't false-hit
        # inside ordinary words like "attached".
        import re

        def has_phrase(term: str) -> bool:
            return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", low) is not None

        financial = any(has_phrase(t) for t in (
            "wire transfer", "routing number", "bank account", "invoice",
            "payment", "funds", "ach", "account number",
        ))
        spoof_ceo = any(k in low for k in ("ceo", "board meeting", "sent from my iphone")) and financial

        delta = 0
        reasons = []
        if urgency and secrecy and financial:
            delta += 20
            reasons.append("urgency + secrecy + financial request (BEC pattern)")
        elif urgency and financial:
            delta += 10
            reasons.append("urgency + financial request")
        if spoof_ceo:
            delta += 10
            reasons.append("possible executive impersonation tone")
        if delta:
            score = self.risk.update(delta, "content-heuristic: " + "; ".join(reasons))
            self.ui.set_risk(score, self.risk.events[-1].reason if self.risk.events else "")
            self.ui.observation("content heuristic: " + "; ".join(reasons))

    def _finalize(self, verdict: str, confidence: int, note: str) -> Dict[str, Any]:
        evidence = [e.reason for e in self.risk.events]
        self.ui.verdict(verdict, confidence)
        statebus.publish(state="verdict", verdict=verdict, risk=self.risk.score,
                         message=f"verdict: {verdict} ({confidence}%)")
        return {
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": self.risk.score,
            "evidence": evidence,
            "note": note,
            "observations": self.observations,
            "risk_events": self.risk.events,
            "geolocation_summary": self.geo_summary,
        }


def answer_copilot_question(data: Dict[str, Any], user_question: str) -> str:
    """Grounded AI Copilot Q&A handler answering strictly from real investigation data."""
    import re

    q = user_question.strip().lower()

    verdict = data.get("verdict", "UNKNOWN")
    risk = data.get("risk_score", 0)
    confidence = data.get("confidence", "Medium")
    why_matters = data.get("why_this_matters") or {}
    threat_story = data.get("threat_story", "")
    breakdown = data.get("score_breakdown") or []

    def has_kw(keywords: tuple[str, ...]) -> bool:
        return any(re.search(rf"\b{re.escape(k)}\b", q) for k in keywords)

    # 1. Safety & Verdict Questions
    if has_kw(("safe", "dangerous", "malicious", "verdict", "risk", "status")):
        if verdict == "SAFE":
            return f"Yes. Sentinel analyzed this email and determined it is SAFE (Risk: {risk}/100, Confidence: {confidence}). All authentication checks passed and no malicious links or attachments were found."
        elif verdict == "MALICIOUS":
            return f"No. Sentinel determined this email is MALICIOUS with a high Risk Score of {risk}/100 ({confidence} Confidence). It contains active threat indicators such as authentication failures or suspicious links."
        else:
            return f"Sentinel flagged this email as SUSPICIOUS (Risk Score: {risk}/100, {confidence} Confidence). Exercise caution before interacting with any links or attachments."

    # 2. Evidence & Indicators Questions (check evidence keywords BEFORE generic why/how)
    if has_kw(("evidence", "indicator", "indicators", "proof", "graph", "link", "links", "attachment", "attachments")):
        if breakdown:
            reasons = "\n".join(f"• {b.get('reason')}" for b in breakdown)
            return f"Key Evidence & Indicators Collected:\n{reasons}"
        return f"Case File: {data.get('case_file', 'n/a')}\nSHA-256 Hash: {data.get('file_hash', 'n/a')}\nVerdict: {verdict} ({risk}/100)"

    # 3. Action & Guidance Questions
    if has_kw(("do", "action", "recommend", "recommendation", "handle", "quarantine", "next step")):
        action_text = why_matters.get("action")
        if action_text:
            return f"Recommended Action:\n{action_text}"
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            return "Do NOT click any links, open attachments, or reply to the email. Quarantine the message and report it to your IT security team."
        return "Proceed normally. Verify the sender if unexpected requests for credentials or financial actions arise."

    # 4. Technical Details Questions
    if has_kw(("technical", "header", "headers", "spf", "dkim", "dmarc", "ip", "whois")):
        tech = data.get("technical_details") or {}
        hdr = tech.get("headers") or {}
        auth = hdr.get("auth") or {}
        return (
            f"Technical Investigation Breakdown:\n"
            f"• Origin IP: {tech.get('origin_ip', 'n/a')}\n"
            f"• SPF Status: {auth.get('spf', 'n/a')}\n"
            f"• DKIM Status: {auth.get('dkim', 'n/a')}\n"
            f"• Total Hyperlinks: {(tech.get('urls') or {}).get('total_links', 0)}\n"
            f"• Attachments Scanned: {len(tech.get('attachments') or [])}"
        )

    # 5. Reasoning / Why Questions
    if has_kw(("why", "reason", "reasons", "how", "cause", "explain")):
        why_text = why_matters.get("why")
        if why_text:
            return f"Why Sentinel reached this conclusion:\n{why_text}"
        if breakdown:
            reasons = "\n".join(f"• {b.get('reason')}" for b in breakdown)
            return f"Sentinel identified the following threat indicators:\n{reasons}"
        return f"Sentinel analyzed email headers, embedded URLs, and sender infrastructure, resulting in a risk score of {risk}/100."

    # 6. Default Summary Answer
    if threat_story:
        return f"Investigation Summary:\n{threat_story}"
    return f"Sentinel finalized investigation for '{data.get('case_file', 'EML Case')}': Verdict is {verdict} with a Risk Score of {risk}/100 ({confidence} Confidence)."

