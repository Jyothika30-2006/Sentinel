"""LLM integration for the reasoning brain.

Two interchangeable providers share one interface (`available`, `chat`,
`extract_tool_calls`, `extract_text`), selected via `make_client()`:

  * OllamaClient        — local Ollama `/api/chat` with native tool calling
                          (Ollama 0.3+, llama3.1 / qwen2.5). Zero cloud.
  * OpenAICompatClient  — ANY OpenAI-compatible `/chat/completions` endpoint
                          (hosted gateways, vLLM, LM Studio, ...). Configured
                          via OPENAI_BASE_URL / OPENAI_API_KEY / OPENAI_MODEL.

Both clients RETURN Ollama-shaped responses (`{"message": {"content",
"tool_calls": [{"function": {"name", "arguments"}}]}}`), so the Agent loop,
message history, and tool-calling code stay provider-agnostic. OpenAI-style
wire details (tool_call ids, JSON-string arguments, tool_call_id on tool
messages) are handled inside OpenAICompatClient.

If the configured provider is unreachable or `--no-llm` is set, the agent
falls back to the deterministic pipeline (same tools, same safety gates).
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import requests

from .config import CONFIG


class OllamaClient:
    """Minimal, dependency-light client for Ollama's tool-calling API."""

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        self.base_url = (base_url or CONFIG.ollama_base_url).rstrip("/")
        self.model = model or CONFIG.ollama_model
        self.timeout = 120  # LLM generation can be slow on CPU

    # --- liveness ----------------------------------------------------
    def available(self) -> bool:
        """Cheap health check: does a local Ollama respond on /api/tags?"""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return r.status_code == 200
        except requests.RequestException:
            return False

    # --- core call ---------------------------------------------------
    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Send a chat request; return the raw Ollama response dict.

        When `tools` is provided, Ollama may respond with
        `message.tool_calls` (list of {function:{name, arguments}}) instead
        of plain text.
        """
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        r = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def extract_tool_calls(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Pull normalized tool calls out of an Ollama response.

        Returns a list of dicts: {"name": str, "arguments": dict}.
        """
        calls = []
        msg = resp.get("message", {}) or {}
        for tc in msg.get("tool_calls", []) or []:
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                # Some models return arguments as a JSON string.
                try:
                    import json

                    args = json.loads(args)
                except Exception:
                    args = {}
            calls.append({"name": fn.get("name"), "arguments": args or {}})
        return calls

    @staticmethod
    def extract_text(resp: Dict[str, Any]) -> str:
        """Pull the plain-text content out of an Ollama response."""
        msg = resp.get("message", {}) or {}
        return (msg.get("content") or "").strip()


class OpenAICompatClient:
    """Client for any OpenAI-compatible /chat/completions endpoint.

    Speaks the OpenAI wire format on the outside but returns Ollama-shaped
    responses on the inside, so `Agent` needs no provider-specific code.
    """

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: int = 120) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = (api_key or "").strip()
        self.model = (model or "").strip()
        self.timeout = timeout
        if not (self.base_url and self.model):
            raise ValueError("OpenAICompatClient needs OPENAI_BASE_URL and OPENAI_MODEL")

    # --- liveness ----------------------------------------------------
    def available(self) -> bool:
        """GET /models first; if the gateway doesn't implement it, fall back
        to a 1-token chat ping."""
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            r = requests.get(f"{self.base_url}/models", headers=headers, timeout=5)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            return False
        try:
            r = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json={"model": self.model,
                      "messages": [{"role": "user", "content": "ping"}],
                      "max_tokens": 1},
                timeout=10,
            )
            return r.status_code == 200
        except requests.RequestException:
            return False

    # --- wire-format conversion ---------------------------------------
    @staticmethod
    def _to_openai_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert the agent's Ollama-shaped history to OpenAI wire format.

        Assistant messages carry Ollama-style tool_calls
        ([{"function": {"name", "arguments": dict}}]); each FOLLOWING tool
        message must reference the matching tool_call_id, in order.
        """
        out: List[Dict[str, Any]] = []
        pending_ids: List[str] = []
        for m in messages:
            role = m.get("role")
            if role == "tool":
                call_id = pending_ids.pop(0) if pending_ids else "call_0"
                out.append({"role": "tool", "tool_call_id": call_id,
                            "content": str(m.get("content", ""))})
                continue
            converted = {"role": role, "content": m.get("content", "") or ""}
            calls = m.get("tool_calls") or []
            if calls:
                wire_calls = []
                for i, tc in enumerate(calls):
                    fn = tc.get("function", {}) or {}
                    args = fn.get("arguments", {})
                    if not isinstance(args, str):
                        args = json.dumps(args or {})
                    call_id = tc.get("id") or f"call_{len(out)}_{i}"
                    wire_calls.append({"id": call_id, "type": "function",
                                       "function": {"name": fn.get("name"),
                                                    "arguments": args}})
                    pending_ids.append(call_id)
                converted["tool_calls"] = wire_calls
            out.append(converted)
        return out

    # --- core call ----------------------------------------------------
    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        max_retries: int = 4,
    ) -> Dict[str, Any]:
        """POST /chat/completions; return an OLLAMA-SHAPED response dict so
        the Agent loop stays provider-agnostic.

        Rate-limited gateways (HTTP 429) are retried with escalating backoff,
        honoring Retry-After when present — one agent step maps to exactly
        one logical request, so transient quota hits must not abort the loop.
        """
        import time

        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": self._to_openai_messages(messages),
        }
        if tools:
            # The registry already emits {"type":"function","function":{...}}
            # which is exactly the OpenAI tool schema — pass through as-is.
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        for attempt in range(max_retries):
            r = requests.post(f"{self.base_url}/chat/completions",
                              headers=headers, json=payload, timeout=self.timeout)
            if r.status_code == 429 and attempt < max_retries - 1:
                try:
                    wait = int(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = 15 * (attempt + 1)
                time.sleep(max(1, min(wait, 60)))
                continue
            r.raise_for_status()
            return self._normalize(r.json())
        r.raise_for_status()
        return self._normalize(r.json())  # unreachable; keeps type-checkers happy

    @staticmethod
    def _normalize(resp: Dict[str, Any]) -> Dict[str, Any]:
        """OpenAI response -> Ollama-shaped response."""
        choice = (resp.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tool_calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            tool_calls.append({"function": {"name": fn.get("name"),
                                            "arguments": args or {}}})
        return {
            "model": resp.get("model", ""),
            "message": {
                "content": (msg.get("content") or "").strip(),
                "tool_calls": tool_calls,
            },
            "_usage": resp.get("usage", {}),
        }

    # --- shared extraction helpers (same contract as OllamaClient) ----
    @staticmethod
    def extract_tool_calls(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
        calls = []
        msg = resp.get("message", {}) or {}
        for tc in msg.get("tool_calls", []) or []:
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            calls.append({"name": fn.get("name"), "arguments": args or {}})
        return calls

    @staticmethod
    def extract_text(resp: Dict[str, Any]) -> str:
        msg = resp.get("message", {}) or {}
        return (msg.get("content") or "").strip()


def make_client() -> Any:
    """Build the configured LLM client (factory used everywhere).

    Provider selection: LLM_PROVIDER=ollama (default) | openai.
    """
    provider = (CONFIG.llm_provider or "ollama").strip().lower()
    if provider in ("openai", "openai_compat", "openai-compatible"):
        return OpenAICompatClient(
            base_url=CONFIG.openai_base_url,
            api_key=CONFIG.openai_api_key,
            model=CONFIG.openai_model,
        )
    return OllamaClient()
