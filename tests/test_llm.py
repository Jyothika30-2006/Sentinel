"""Tests for the multi-provider LLM layer (sentinel/llm.py).

OpenAICompatClient must be wire-compatible with any OpenAI-style
/chat/completions endpoint while exposing the Ollama-shaped interface the
Agent loop expects. All network I/O is mocked here; the live provider is
exercised separately (manual / CLI).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from sentinel import llm as llm_mod
from sentinel.config import Config
from sentinel.llm import OpenAICompatClient, OllamaClient, make_client


CLIENT = OpenAICompatClient("https://api.example.test/v1", "sk-test", "hy3")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
class TestFactory:
    def test_defaults_to_ollama(self, monkeypatch):
        cfg = Config()
        cfg.llm_provider = "ollama"
        monkeypatch.setattr(llm_mod, "CONFIG", cfg)
        assert isinstance(make_client(), OllamaClient)

    def test_openai_provider(self, monkeypatch):
        cfg = Config()
        cfg.llm_provider = "openai"
        cfg.openai_base_url = "https://api.example.test/v1"
        cfg.openai_api_key = "sk-test"
        cfg.openai_model = "hy3"
        monkeypatch.setattr(llm_mod, "CONFIG", cfg)
        assert isinstance(make_client(), OpenAICompatClient)

    def test_openai_provider_missing_settings_raises(self, monkeypatch):
        cfg = Config()
        cfg.llm_provider = "openai"
        cfg.openai_base_url = ""
        monkeypatch.setattr(llm_mod, "CONFIG", cfg)
        with pytest.raises(ValueError):
            make_client()


# ---------------------------------------------------------------------------
# Wire-format conversion (Ollama-shaped history -> OpenAI wire format)
# ---------------------------------------------------------------------------
class TestMessageConversion:
    def test_plain_messages_pass_through(self):
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        out = CLIENT._to_openai_messages(msgs)
        assert out == msgs

    def test_tool_calls_get_ids_and_string_args(self):
        msgs = [
            {"role": "user", "content": "investigate"},
            {"role": "assistant", "content": "",
             "tool_calls": [{"function": {"name": "parse_headers",
                                          "arguments": {"email_path": "a.eml"}}}]},
        ]
        out = CLIENT._to_openai_messages(msgs)
        tc = out[1]["tool_calls"][0]
        assert tc["type"] == "function"
        assert tc["function"]["name"] == "parse_headers"
        assert json.loads(tc["function"]["arguments"]) == {"email_path": "a.eml"}
        assert tc["id"]

    def test_tool_messages_reference_call_ids_in_order(self):
        msgs = [
            {"role": "assistant", "content": "",
             "tool_calls": [
                 {"function": {"name": "t1", "arguments": {}}},
                 {"function": {"name": "t2", "arguments": {}}},
             ]},
            {"role": "tool", "content": "result-1"},
            {"role": "tool", "content": "result-2"},
        ]
        out = CLIENT._to_openai_messages(msgs)
        ids = [tc["id"] for tc in out[0]["tool_calls"]]
        assert out[1]["tool_call_id"] == ids[0]
        assert out[2]["tool_call_id"] == ids[1]


# ---------------------------------------------------------------------------
# Response normalization (OpenAI shape -> Ollama shape)
# ---------------------------------------------------------------------------
class TestNormalize:
    def test_full_shape(self):
        resp = {
            "model": "hy3",
            "choices": [{"message": {
                "content": "thinking...",
                "tool_calls": [{"id": "c1", "type": "function",
                                "function": {"name": "hash_evidence",
                                             "arguments": "{\"email_path\": \"x.eml\"}"}}],
            }}],
            "usage": {"total_tokens": 42},
        }
        norm = OpenAICompatClient._normalize(resp)
        assert norm["message"]["content"] == "thinking..."
        tc = norm["message"]["tool_calls"][0]["function"]
        assert tc["name"] == "hash_evidence"
        assert tc["arguments"] == {"email_path": "x.eml"}

    def test_empty_choices(self):
        norm = OpenAICompatClient._normalize({"choices": []})
        assert norm["message"]["content"] == ""
        assert norm["message"]["tool_calls"] == []

    def test_extract_helpers_match_ollama_contract(self):
        resp = {"message": {"content": "hello", "tool_calls": [
            {"function": {"name": "t", "arguments": "{\"a\": 1}"}}]}}
        assert OpenAICompatClient.extract_text(resp) == "hello"
        calls = OpenAICompatClient.extract_tool_calls(resp)
        assert calls == [{"name": "t", "arguments": {"a": 1}}]


# ---------------------------------------------------------------------------
# chat() + available() with mocked transport
# ---------------------------------------------------------------------------
class TestTransport:
    def test_chat_sends_openai_payload_and_normalizes(self, monkeypatch):
        captured = {}

        class FakeResp:
            status_code = 200
            def raise_for_status(self):
                pass
            def json(self):
                return {"model": "hy3", "choices": [{"message": {
                    "content": "", "tool_calls": [
                        {"id": "c1", "function": {"name": "extract_urls",
                                                  "arguments": "{\"body\": \"hi\"}"}}]}}]}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResp()

        monkeypatch.setattr(llm_mod.requests, "post", fake_post)
        resp = CLIENT.chat(
            [{"role": "user", "content": "go"}],
            tools=[{"type": "function", "function": {"name": "extract_urls",
                                                     "parameters": {}}}],
        )
        assert captured["url"].endswith("/chat/completions")
        assert captured["headers"]["Authorization"] == "Bearer sk-test"
        assert captured["json"]["model"] == "hy3"
        assert captured["json"]["tool_choice"] == "auto"
        assert captured["json"]["tools"][0]["type"] == "function"
        assert resp["message"]["tool_calls"][0]["function"]["name"] == "extract_urls"

    def test_available_via_models_endpoint(self, monkeypatch):
        class FakeResp:
            status_code = 200
        monkeypatch.setattr(llm_mod.requests, "get",
                            lambda url, headers=None, timeout=None: FakeResp())
        assert CLIENT.available() is True

    def test_available_falls_back_to_ping(self, monkeypatch):
        class R404:
            status_code = 404
        class R200:
            status_code = 200
        monkeypatch.setattr(llm_mod.requests, "get",
                            lambda url, headers=None, timeout=None: R404())
        monkeypatch.setattr(llm_mod.requests, "post",
                            lambda url, headers=None, json=None, timeout=None: R200())
        assert CLIENT.available() is True

    def test_unreachable_is_not_available(self, monkeypatch):
        def boom(*a, **k):
            raise llm_mod.requests.RequestException("down")
        monkeypatch.setattr(llm_mod.requests, "get", boom)
        assert CLIENT.available() is False
