"""Central Investigation Orchestrator (`sentinel/orchestrator.py`).

Coordinates all Sentinel security analysis modules into a single, unified investigation pipeline:

Email/File Input -> Email Engine -> Threat Intel -> File Engine -> Correlation -> Risk & Confidence Engine -> AI Reasoner & Explainability -> Report & Blockchain Ledger.
"""
from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import explain, statebus
from .blockchain.hashchain import HashChain
from .risk import RiskTracker
from .tools import (
    _emailutil,
    check_reputation,
    check_tor_exit,
    dnsintel,
    extract_urls,
    geolocate_ip,
    hash_evidence,
    parse_headers,
    resolve_origin,
    static_file_scan,
)


class InvestigationOrchestrator:
    def __init__(self) -> None:
        self.chain = HashChain()

    def run_investigation(self, email_path: str, auto_confirm: bool = True) -> Dict[str, Any]:
        """Execute a full, coordinated investigation on an .eml file."""
        email_path = os.path.abspath(email_path)
        if not os.path.exists(email_path):
            raise FileNotFoundError(f"Case file not found: {email_path}")

        start_time = time.time()
        timeline: List[Dict[str, str]] = []

        def log_timeline(phase: str, event: str):
            ts = datetime.now().strftime("%H:%M:%S")
            timeline.append({"timestamp": ts, "phase": phase, "event": event})
            statebus.publish(state="investigating", message=f"[{phase}] {event}")

        log_timeline("Initialization", f"Started forensic investigation on {Path(email_path).name}")

        # 1. HASH EVIDENCE
        log_timeline("Evidence Hashing", "Calculating cryptographic SHA-256 evidence hash")
        hash_res = hash_evidence.hash_evidence(email_path)
        file_hash = hash_res.get("email_sha256") or hash_res.get("sha256", "")

        # 2. PARSE EMAIL & HEADERS
        log_timeline("Header Forensics", "Parsing email headers and Received: hop chain")
        msg = _emailutil.parse_email(email_path)
        raw_headers = _emailutil.get_headers(msg)
        hdr_info = parse_headers.parse_headers(email_path)

        # 3. ORIGIN RESOLUTION & GEOLOCATION
        log_timeline("Origin Resolution", "Tracing originating IP address through Received hops")
        origin_info = resolve_origin.resolve_origin(hdr_info)
        origin_ip = origin_info.get("origin_ip")

        geo_info = {}
        tor_info = {}
        if origin_ip:
            log_timeline("IP Geolocation", f"Geolocating origin IP {origin_ip}")
            geo_info = geolocate_ip.geolocate_ip(origin_ip)
            log_timeline("Tor Exit Check", f"Checking Tor DNSEL for {origin_ip}")
            tor_info = check_tor_exit.check_tor_exit(origin_ip)

        # 4. URL EXTRACTION & ANALYSIS
        log_timeline("URL Analysis", "Extracting body hyperlinks and checking brand typosquatting")
        body_text = _emailutil.get_body(msg)
        url_info = extract_urls.extract_urls(body_text)

        # 5. DNS INTEL & WHOIS ON DOMAINS
        dns_info = {}
        whois_info = {}
        from_domain = ""
        from_header = hdr_info.get("From", "")
        if "@" in from_header:
            from_domain = from_header.split("@")[-1].split(">")[0].strip().lower()

        if from_domain:
            log_timeline("DNS Intelligence", f"Performing DNS lookup for sender domain {from_domain}")
            dns_info = dnsintel.dns_lookup(from_domain)
            log_timeline("WHOIS Intelligence", f"Performing WHOIS registration check for {from_domain}")
            whois_info = dnsintel.whois_lookup(from_domain)

        # 6. ATTACHMENT SCANNING
        log_timeline("Attachment Analysis", "Extracting and scanning attachments")
        attachment_scans = []
        outdir = os.path.join(os.path.dirname(email_path), "extracted_attachments")
        saved_paths = _emailutil.extract_attachments(msg, outdir)
        for path in saved_paths:
            try:
                scan_res = static_file_scan.static_file_scan(path)
                attachment_scans.append(scan_res)
            except Exception as exc:
                attachment_scans.append({"path": path, "error": str(exc)})

        # 7. THREAT CORRELATION & RISK SCORING
        log_timeline("Threat Correlation", "Correlating findings and calculating explainable risk score")
        risk_tracker = RiskTracker()

        # Evaluate Authentication
        auth = hdr_info.get("auth", {})
        spf = auth.get("spf", "none")
        dkim = auth.get("dkim", "none")
        if spf in ("fail", "softfail"):
            risk_tracker.update(25, f"SPF authentication check failed ({spf})")
        if dkim in ("fail", "softfail"):
            risk_tracker.update(20, f"DKIM digital signature failed ({dkim})")

        # Evaluate Impersonation
        if from_domain and from_domain != origin_info.get("origin_domain"):
            display_name = from_header.split("<")[0].strip() if "<" in from_header else from_header
            if any(b in display_name.lower() for b in ("paypal", "apple", "microsoft", "google", "bank", "admin")):
                risk_tracker.update(30, f"Sender impersonation detected: '{display_name}' vs domain '{from_domain}'")

        # Evaluate Tor Exit
        if tor_info.get("tor_exit"):
            risk_tracker.update(25, f"Origin IP {origin_ip} is an active Tor exit node")

        # Evaluate URLs
        for link in url_info.get("links", []):
            rc = link.get("risk_contribution", 0)
            if rc > 0:
                flags_str = ", ".join(link.get("flags", []))
                risk_tracker.update(min(rc, 30), f"Suspicious URL ({link.get('domain')}): {flags_str}")

        # Evaluate Attachments
        for att in attachment_scans:
            att_path = att.get("attachment", "")
            ext = Path(att_path).suffix.lower()
            if ext in (".exe", ".vbs", ".bat", ".ps1", ".scr", ".iso", ".xlsm", ".docm"):
                risk_tracker.update(35, f"Dangerous attachment extension '{ext}' in {Path(att_path).name}")

        final_risk = risk_tracker.score

        # Determine Verdict
        if final_risk >= 80:
            verdict = "MALICIOUS"
        elif final_risk >= 35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Determine Confidence
        source_count = 1  # header parser
        if geo_info.get("sources_queried", 0) > 0 or geo_info.get("country"):
            source_count += 1
        if url_info.get("total_links", 0) > 0:
            source_count += 1
        if from_domain and dns_info.get("a"):
            source_count += 1
        if attachment_scans:
            source_count += 1

        if source_count >= 3 and final_risk > 0:
            confidence = "High"
            conf_pct = 95
        elif source_count >= 2:
            confidence = "Medium"
            conf_pct = 80
        else:
            confidence = "Low"
            conf_pct = 65

        log_timeline("Verdict Determination", f"Investigation finalized: {verdict} (Risk: {final_risk}/100, Confidence: {confidence})")

        # 8. BUILD EXPLANATION & THREAT STORY
        indicators = [{"delta": e.delta, "reason": e.reason} for e in risk_tracker.events]
        why_matters = explain.generate_why_this_matters(indicators, verdict, final_risk)
        threat_story = explain.generate_threat_story(hdr_info, url_info.get("links", []), saved_paths, indicators, verdict)

        # 9. BUILD EVIDENCE GRAPH
        nodes = []
        edges = []

        # Node: Email Case
        case_id = f"case_{file_hash[:8]}"
        nodes.append({"id": case_id, "label": Path(email_path).name, "type": "case", "risk": final_risk})

        # Node: Sender
        sender_id = None
        if from_header:
            sender_id = f"sender_{hash(from_header) & 0xffffffff}"
            nodes.append({"id": sender_id, "label": from_header, "type": "sender"})
            edges.append({"from": case_id, "to": sender_id, "label": "SENT_BY"})

        # Node: Domain
        domain_id = None
        if from_domain:
            domain_id = f"domain_{from_domain}"
            nodes.append({"id": domain_id, "label": from_domain, "type": "domain"})
            if sender_id:
                edges.append({"from": sender_id, "to": domain_id, "label": "DOMAIN"})

        # Node: Origin IP
        if origin_ip:
            ip_id = f"ip_{origin_ip}"
            nodes.append({"id": ip_id, "label": origin_ip, "type": "ip", "geo": geo_info.get("city", "")})
            if domain_id:
                edges.append({"from": domain_id, "to": ip_id, "label": "RESOLVES_TO"})

        # Nodes: URLs
        for i, link in enumerate(url_info.get("links", [])[:5]):
            u_domain = link.get("domain", "")
            if u_domain:
                url_node_id = f"url_{i}_{u_domain}"
                nodes.append({"id": url_node_id, "label": u_domain, "type": "url", "risk": link.get("risk_contribution", 0)})
                edges.append({"from": case_id, "to": url_node_id, "label": "CONTAINS_URL"})

        # Nodes: Attachments
        for i, att_p in enumerate(saved_paths):
            att_name = Path(att_p).name
            att_id = f"att_{i}_{att_name}"
            nodes.append({"id": att_id, "label": att_name, "type": "attachment"})
            edges.append({"from": case_id, "to": att_id, "label": "HAS_ATTACHMENT"})

        evidence_graph = {"nodes": nodes, "edges": edges}

        # 10. RECORD EVIDENCE IN BLOCKCHAIN LEDGER
        log_timeline("Blockchain Ledger", "Recording tamper-proof evidence block in HashChain ledger")
        ledger_block = self.chain.append({
            "case_file": Path(email_path).name,
            "file_hash": file_hash,
            "ai_verdict": verdict,
            "risk_score": final_risk,
            "confidence_score": conf_pct,
            "indicators_count": len(indicators),
        })

        log_timeline("Completion", "Investigation workflow complete. Report generated.")

        # Update Statebus
        statebus.publish(
            state="verdict",
            verdict=verdict,
            risk=final_risk,
            message=f"{verdict} ({final_risk}/100) — {why_matters.get('what')}",
        )

        return {
            "case_file": Path(email_path).name,
            "file_hash": file_hash,
            "verdict": verdict,
            "risk_score": final_risk,
            "confidence": confidence,
            "confidence_score": conf_pct,
            "summary": why_matters.get("what"),
            "threat_story": threat_story,
            "why_this_matters": why_matters,
            "timeline": timeline,
            "evidence_graph": evidence_graph,
            "score_breakdown": [
                {"category": e.reason.split(":")[0], "points": e.delta, "reason": e.reason}
                for e in risk_tracker.events
            ],
            "technical_details": {
                "headers": hdr_info,
                "origin_ip": origin_ip,
                "geolocation": geo_info,
                "urls": url_info,
                "dns": dns_info,
                "whois": whois_info,
                "attachments": attachment_scans,
            },
            "ledger_block": ledger_block,
            "elapsed_seconds": round(time.time() - start_time, 2),
        }


# Singleton orchestrator instance
orchestrator = InvestigationOrchestrator()
