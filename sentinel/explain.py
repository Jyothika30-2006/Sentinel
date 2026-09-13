"""Sentinel Human Explanation & Translation Engine.

Converts raw technical indicators (SPF=FAIL, DKIM=NONE, DMARC=FAIL, ASN=12345, URL_SCORE=0.91)
into clear, understandable English for non-technical users.

Provides:
- `explain_indicator(key, value)`
- `generate_why_this_matters(indicators, verdict, risk_score)`
- `generate_threat_story(headers, urls, attachments, indicators, verdict)`
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


TECHNICAL_TRANSLATIONS = {
    "spf_fail": "The sender's domain failed email authentication (SPF). The email server could not verify that the message originated from an authorized server.",
    "dkim_fail": "The digital signature (DKIM) is invalid or missing, meaning the email contents may have been modified in transit.",
    "dmarc_fail": "DMARC policy check failed. The sender's identity cannot be trusted and appears forged.",
    "typosquat": "Contains a web link pointing to a domain designed to mimic a legitimate organization's address.",
    "brand_mismatch": "The email displays a trusted brand name, but the embedded links point to an unrelated external website.",
    "raw_ip_url": "Contains a hyperlink pointing directly to a numeric IP address rather than a domain name, commonly used by credential-harvesting sites.",
    "at_trick_url": "Uses an @-trick in the URL to obfuscate the real destination website.",
    "punycode_domain": "Uses an Internationalized Domain Name (Punycode) to visually imitate a standard domain name.",
    "tor_exit": "The origin IP address belongs to an active Tor exit node, indicating the sender deliberately concealed their geographic origin.",
    "malicious_attachment": "Contains a high-risk or executable attachment format that could run malicious code if opened.",
    "sender_impersonation": "The display name matches a trusted executive or service, but the actual email address belongs to an external third party.",
}


def explain_indicator(key: str, default_msg: str = "") -> str:
    """Translate a technical key or message into clear English."""
    k = key.lower()
    for pattern, text in TECHNICAL_TRANSLATIONS.items():
        if pattern in k:
            return text
    return default_msg or key


def generate_why_this_matters(indicators: List[Dict[str, Any]], verdict: str, risk_score: int) -> Dict[str, str]:
    """Generate structured What, Why, Impact, Action framework."""
    if verdict == "SAFE" or risk_score < 35:
        return {
            "what": "Sentinel analyzed this email and verified its sender authentication, links, and attachments.",
            "why": "All email authentication checks (SPF/DKIM/DMARC) passed, and no malicious URLs or risky attachments were detected.",
            "impact": "This email appears legitimate. Normal interaction carries low risk.",
            "action": "Proceed normally. As always, remain vigilant if unexpected requests for sensitive data arise.",
        }

    high_risk_reasons = []
    for ind in indicators:
        msg = ind.get("reason") or ind.get("message") or ""
        translated = explain_indicator(msg, msg)
        if translated and translated not in high_risk_reasons:
            high_risk_reasons.append(translated)

    why_prose = " ".join(high_risk_reasons[:3]) if high_risk_reasons else "Multiple suspicious indicators were detected during forensic analysis."

    if verdict == "MALICIOUS" or risk_score >= 80:
        return {
            "what": "Sentinel detected an active cyber threat in this email message.",
            "why": why_prose,
            "impact": "Interacting with links or attachments in this email could result in credential theft, ransomware infection, or unauthorized access to corporate accounts.",
            "action": "Do NOT click any links, open attachments, or reply. Report this email to your IT security team and quarantine it immediately.",
        }

    return {
        "what": "Sentinel flagged this email as suspicious due to anomalous security indicators.",
        "why": why_prose,
        "impact": "Entering credentials or opening attachments from this sender could expose sensitive account information.",
        "action": "Exercise caution. Do not click links or open attachments. Verify the sender's identity through a trusted alternative channel (e.g. phone call or official web portal).",
    }


def generate_threat_story(headers: Dict[str, Any], urls: List[Dict[str, Any]], attachments: List[Any], indicators: List[Dict[str, Any]], verdict: str) -> str:
    """Generate a human-readable attack narrative describing intent."""
    from_addr = headers.get("From", "Unknown Sender")
    subject = headers.get("Subject", "(No Subject)")

    if verdict == "SAFE":
        return f"Sentinel performed full forensic analysis on the email '{subject}' from '{from_addr}'. All email authentication signatures (SPF/DKIM) were verified, embedded links resolve to legitimate domains, and no suspicious attachments were found."

    story_parts = [f"The email '{subject}' claims to be sent from '{from_addr}'."]

    # Authentication story
    auth = headers.get("auth", {})
    if auth.get("spf") in ("fail", "softfail") or auth.get("dmarc") in ("fail", "softfail"):
        story_parts.append("Email authentication checks (SPF/DMARC) failed, indicating that the sender address was spoofed or sent through an unauthorized server.")

    # URL story
    bad_urls = [u for u in urls if u.get("risk_contribution", 0) > 0 or u.get("flags")]
    if bad_urls:
        url_domains = ", ".join({u.get("domain", "") for u in bad_urls if u.get("domain")})
        story_parts.append(f"The message contains deceptive web links (pointing to {url_domains}) designed to redirect the user to suspicious or typosquitted login pages.")

    # Attachment story
    if attachments:
        story_parts.append(f"The message includes {len(attachments)} attachment(s) that require static forensic analysis.")

    if verdict == "MALICIOUS":
        story_parts.append("Together, these indicators point to a high-confidence phishing or credential-harvesting attempt. The attacker intends to deceive the recipient into surrendering credentials or installing harmful software.")
    else:
        story_parts.append("These suspicious anomalies suggest a possible impersonation or social engineering attempt. Caution is advised.")

    return " ".join(story_parts)
