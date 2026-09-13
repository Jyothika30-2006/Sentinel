"""Unit tests for Sentinel Orchestrator, Explanation Engine, and Copilot Q&A."""
from __future__ import annotations

import os
from pathlib import Path
import pytest

from sentinel import explain
from sentinel.orchestrator import InvestigationOrchestrator
from sentinel.agent import answer_copilot_question

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


class TestExplainEngine:
    def test_explain_indicator(self):
        assert "SPF" in explain.explain_indicator("spf_fail")
        assert "DKIM" in explain.explain_indicator("dkim_fail")
        assert "typosquitted" in explain.explain_indicator("typosquat") or "mimic" in explain.explain_indicator("typosquat")
        assert explain.explain_indicator("unknown_key", "default message") == "default message"

    def test_generate_why_this_matters_safe(self):
        res = explain.generate_why_this_matters([], "SAFE", 10)
        assert "what" in res
        assert "why" in res
        assert "impact" in res
        assert "action" in res
        assert "SAFE" not in res["what"] or "analyzed" in res["what"]

    def test_generate_why_this_matters_malicious(self):
        indicators = [{"reason": "spf_fail"}, {"reason": "typosquat"}]
        res = explain.generate_why_this_matters(indicators, "MALICIOUS", 85)
        assert "active cyber threat" in res["what"].lower() or "detected" in res["what"].lower()
        assert res["action"] is not None

    def test_generate_threat_story(self):
        headers = {"From": "test@example.com", "Subject": "Urgent Invoice", "auth": {"spf": "fail"}}
        urls = [{"domain": "login-fake.com", "risk_contribution": 20}]
        story = explain.generate_threat_story(headers, urls, [], [], "MALICIOUS")
        assert "Urgent Invoice" in story
        assert "test@example.com" in story
        assert "login-fake.com" in story


class TestOrchestrator:
    def test_run_investigation_sample(self):
        eml_file = SAMPLES_DIR / "phishing.eml"
        if not eml_file.exists():
            pytest.skip("phishing.eml sample not found")

        orch = InvestigationOrchestrator()
        result = orch.run_investigation(str(eml_file), auto_confirm=True)

        assert "verdict" in result
        assert result["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")
        assert "risk_score" in result
        assert 0 <= result["risk_score"] <= 100
        assert "why_this_matters" in result
        assert "threat_story" in result
        assert "timeline" in result
        assert len(result["timeline"]) > 0
        assert "evidence_graph" in result
        assert "nodes" in result["evidence_graph"]
        assert "edges" in result["evidence_graph"]
        assert "ledger_block" in result
        assert result["ledger_block"]["hash"] is not None


class TestCopilotQA:
    @pytest.fixture
    def mock_case_data(self):
        return {
            "case_file": "phishing.eml",
            "file_hash": "a1b2c3d4e5f67890",
            "verdict": "MALICIOUS",
            "risk_score": 85,
            "confidence": "High",
            "threat_story": "Attacker sent a spoofed email to harvest credentials.",
            "why_this_matters": {
                "what": "Sentinel detected an active cyber threat.",
                "why": "The sender's domain failed email authentication (SPF). Contains web links to typosquitted domain.",
                "impact": "Credentials could be stolen.",
                "action": "Do NOT click links or open attachments.",
            },
            "score_breakdown": [
                {"category": "SPF", "points": 25, "reason": "SPF authentication check failed (fail)"},
                {"category": "URL", "points": 30, "reason": "Suspicious URL (login-fake.com): typosquat"},
            ],
            "technical_details": {
                "origin_ip": "192.168.1.1",
                "headers": {"auth": {"spf": "fail", "dkim": "fail"}},
                "urls": {"total_links": 2},
                "attachments": [],
            },
        }

    def test_verdict_questions(self, mock_case_data):
        ans1 = answer_copilot_question(mock_case_data, "Is this email safe?")
        assert "No" in ans1 or "MALICIOUS" in ans1

    def test_why_questions(self, mock_case_data):
        ans2 = answer_copilot_question(mock_case_data, "Why was this flagged as malicious?")
        assert "SPF" in ans2 or "authentication" in ans2 or "conclusion" in ans2

    def test_action_questions(self, mock_case_data):
        ans3 = answer_copilot_question(mock_case_data, "What should I do?")
        assert "Do NOT click" in ans3 or "quarantine" in ans3.lower()

    def test_evidence_questions(self, mock_case_data):
        ans4 = answer_copilot_question(mock_case_data, "Show me the evidence")
        assert "SPF authentication check failed" in ans4 or "Evidence" in ans4

    def test_technical_questions(self, mock_case_data):
        ans5 = answer_copilot_question(mock_case_data, "Give me technical details like SPF and IP")
        assert "192.168.1.1" in ans5
        assert "SPF Status: fail" in ans5
