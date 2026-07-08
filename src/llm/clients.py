from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from src.llm.base import ChatResult, LLMClient, LLMError


def _http_json(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout: int = 90,
) -> Dict[str, Any]:
    """POST JSON and return the parsed response, mapping failures to LLMError."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise LLMError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"Cannot reach {url}: {exc.reason}") from exc
    except (TimeoutError, json.JSONDecodeError) as exc:
        raise LLMError(f"Bad response from {url}: {exc}") from exc


def _schema_instruction(json_schema: Optional[Dict[str, Any]]) -> str:
    if not json_schema:
        return ""
    return (
        "\n\nReturn ONLY a single JSON object that conforms to this schema, "
        "with no markdown fences or prose:\n" + json.dumps(json_schema)
    )


class AnthropicClient(LLMClient):
    """Claude via the official ``anthropic`` SDK (structured outputs when asked)."""

    provider = "anthropic"

    def _client(self):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on install
            raise LLMError("The 'anthropic' package is not installed. Run: pip install anthropic") from exc
        if not self.api_key:
            raise LLMError("Anthropic requires an API key (set ANTHROPIC_API_KEY or enter it in the wizard).")
        return anthropic.Anthropic(api_key=self.api_key)

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_schema: Optional[Dict[str, Any]] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
    ) -> ChatResult:
        client = self._client()
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if json_schema:
            kwargs["output_config"] = {
                "format": {"type": "json_schema", "schema": json_schema}
            }
        try:
            resp = client.messages.create(**kwargs)
        except Exception as exc:  # SDK raises typed errors; keep message user-safe
            raise LLMError(f"Anthropic request failed: {exc}") from exc
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return ChatResult(text=text, provider=self.provider, model=self.model, raw={"id": getattr(resp, "id", "")})

    def health_check(self) -> None:
        if not self.api_key:
            raise LLMError("Missing Anthropic API key.")
        # Cheap validation without spending tokens: the SDK must be importable.
        self._client()


class OpenAICompatibleClient(LLMClient):
    """Any OpenAI Chat Completions-compatible endpoint.

    Reused for OpenAI, Groq, Mistral, OpenRouter, Together, and self-hosted
    gateways by varying ``base_url``. Uses raw HTTP so it needs no SDK.
    """

    provider = "openai"

    def __init__(self, model: str, api_key: Optional[str] = None, base_url: str = "https://api.openai.com/v1", **options: Any) -> None:
        super().__init__(model, api_key, **options)
        self.base_url = base_url.rstrip("/")

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_schema: Optional[Dict[str, Any]] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
    ) -> ChatResult:
        if not self.api_key:
            raise LLMError(f"{self.provider} requires an API key.")
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system + _schema_instruction(json_schema)},
                {"role": "user", "content": prompt},
            ],
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if json_schema:
            payload["response_format"] = {"type": "json_object"}
        data = _http_json(
            f"{self.base_url}/chat/completions",
            payload,
            {"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected response shape from {self.base_url}: {exc}") from exc
        return ChatResult(text=text, provider=self.provider, model=self.model, raw={"id": data.get("id", "")})

    def health_check(self) -> None:
        if not self.api_key:
            raise LLMError(f"Missing {self.provider} API key.")


class GeminiClient(LLMClient):
    """Google Gemini via the public generativelanguage REST API (no SDK needed)."""

    provider = "gemini"
    _BASE = "https://generativelanguage.googleapis.com/v1beta"

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_schema: Optional[Dict[str, Any]] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
    ) -> ChatResult:
        if not self.api_key:
            raise LLMError("Gemini requires an API key (Google AI Studio key).")
        payload: Dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt + _schema_instruction(json_schema)}]}],
            "generationConfig": {"maxOutputTokens": max_tokens},
        }
        if json_schema:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        url = f"{self._BASE}/models/{self.model}:generateContent?key={self.api_key}"
        data = _http_json(url, payload, {})
        try:
            text = "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected Gemini response: {exc}") from exc
        return ChatResult(text=text, provider=self.provider, model=self.model, raw={})

    def health_check(self) -> None:
        if not self.api_key:
            raise LLMError("Missing Gemini API key.")


class OllamaClient(LLMClient):
    """Local models served by Ollama (no API key)."""

    provider = "ollama"

    def __init__(self, model: str, api_key: Optional[str] = None, base_url: str = "http://localhost:11434", **options: Any) -> None:
        super().__init__(model, api_key, **options)
        self.base_url = base_url.rstrip("/")

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_schema: Optional[Dict[str, Any]] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
    ) -> ChatResult:
        payload: Dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system + _schema_instruction(json_schema)},
                {"role": "user", "content": prompt},
            ],
            "options": {"num_predict": max_tokens},
        }
        if json_schema:
            payload["format"] = "json"
        data = _http_json(f"{self.base_url}/api/chat", payload, {})
        text = (data.get("message") or {}).get("content", "")
        return ChatResult(text=text, provider=self.provider, model=self.model, raw={})

    def health_check(self) -> None:
        try:
            urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5).read()
        except Exception as exc:
            raise LLMError(f"Ollama not reachable at {self.base_url}: {exc}") from exc


def list_ollama_models(base_url: str = "http://localhost:11434") -> List[str]:
    """Return locally-available Ollama model names, or [] if the daemon is down."""
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/api/tags", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [m["name"] for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []
