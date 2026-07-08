from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from src.llm.base import LLMClient, LLMError
from src.llm.clients import (
    AnthropicClient,
    GeminiClient,
    OllamaClient,
    OpenAICompatibleClient,
    list_ollama_models,
)


@dataclass
class ProviderSpec:
    """Everything the wizard needs to render a provider and build its client."""

    id: str
    label: str
    requires_api_key: bool
    default_model: str
    models: List[str] = field(default_factory=list)
    api_key_env: Optional[str] = None
    api_key_hint: str = ""
    base_url: Optional[str] = None
    # Optional callable returning live model ids given (api_key, base_url).
    fetch_models: Optional[Callable[[Optional[str], Optional[str]], List[str]]] = None
    builder: Optional[Callable[..., LLMClient]] = None
    note: str = ""

    def build(self, model: str, api_key: Optional[str] = None) -> LLMClient:
        if self.builder is None:
            raise LLMError(f"Provider '{self.id}' has no runnable backend.")
        kwargs = {}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return self.builder(model=model, api_key=api_key, **kwargs)

    def available_models(self, api_key: Optional[str] = None) -> List[str]:
        if self.fetch_models is not None:
            live = self.fetch_models(api_key, self.base_url)
            if live:
                return live
        return list(self.models)


# ── Provider catalog ─────────────────────────────────────────────────
# Adding a provider is a single entry here; the wizard and CLI pick it up.
PROVIDERS: Dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        id="anthropic",
        label="Anthropic  (Claude)",
        requires_api_key=True,
        api_key_env="ANTHROPIC_API_KEY",
        api_key_hint="sk-ant-...",
        default_model="claude-opus-4-8",
        models=["claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5", "claude-fable-5"],
        builder=AnthropicClient,
        note="Strongest reasoning for severity adjudication and attack-path synthesis.",
    ),
    "openai": ProviderSpec(
        id="openai",
        label="OpenAI  (GPT)",
        requires_api_key=True,
        api_key_env="OPENAI_API_KEY",
        api_key_hint="sk-...",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o",
        models=["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini"],
        builder=OpenAICompatibleClient,
    ),
    "gemini": ProviderSpec(
        id="gemini",
        label="Google  (Gemini)",
        requires_api_key=True,
        api_key_env="GEMINI_API_KEY",
        api_key_hint="AIza...",
        default_model="gemini-2.0-flash",
        models=["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        builder=GeminiClient,
    ),
    "groq": ProviderSpec(
        id="groq",
        label="Groq  (fast OSS)",
        requires_api_key=True,
        api_key_env="GROQ_API_KEY",
        api_key_hint="gsk_...",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        models=["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
        builder=OpenAICompatibleClient,
    ),
    "openrouter": ProviderSpec(
        id="openrouter",
        label="OpenRouter  (many models)",
        requires_api_key=True,
        api_key_env="OPENROUTER_API_KEY",
        api_key_hint="sk-or-...",
        base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-opus-4-8",
        models=["anthropic/claude-opus-4-8", "openai/gpt-4o", "google/gemini-2.0-flash-001", "meta-llama/llama-3.3-70b-instruct"],
        builder=OpenAICompatibleClient,
    ),
    "ollama": ProviderSpec(
        id="ollama",
        label="Ollama  (local, no key)",
        requires_api_key=False,
        base_url="http://localhost:11434",
        default_model="llama3",
        models=["llama3"],
        fetch_models=lambda _key, base: list_ollama_models(base or "http://localhost:11434"),
        builder=OllamaClient,
        note="Runs offline against models pulled with `ollama pull`.",
    ),
    "none": ProviderSpec(
        id="none",
        label="None  (deterministic rules only)",
        requires_api_key=False,
        default_model="rules",
        models=["rules"],
        builder=None,
        note="No LLM. Uses the built-in rule engine for scoring and correlation.",
    ),
}


def list_providers() -> List[ProviderSpec]:
    return list(PROVIDERS.values())


def get_provider(provider_id: str) -> ProviderSpec:
    spec = PROVIDERS.get(provider_id)
    if spec is None:
        raise LLMError(f"Unknown provider '{provider_id}'. Known: {', '.join(PROVIDERS)}")
    return spec


def build_client(provider_id: str, model: str, api_key: Optional[str] = None) -> Optional[LLMClient]:
    """Return a ready client, or ``None`` for the deterministic 'none' provider."""
    spec = get_provider(provider_id)
    if spec.builder is None:
        return None
    return spec.build(model=model, api_key=api_key)


def load_client_from_config(path: str = ".recon_llm_config.json") -> Optional[LLMClient]:
    """Build a client from the persisted wizard config, or ``None`` if unavailable.

    Used by background components (e.g. the controller's attack planner) that don't
    receive the client directly. Never raises — a missing/invalid config or an
    unbuildable provider yields ``None`` (deterministic behaviour).
    """
    cfg_path = Path(path)
    if not cfg_path.exists():
        return None
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        provider = str(cfg.get("provider", "")) or "none"
        model = str(cfg.get("model", "")) or get_provider(provider).default_model
        api_key = cfg.get("api_key") or None
        return build_client(provider, model, api_key)
    except (json.JSONDecodeError, OSError, LLMError):
        return None
