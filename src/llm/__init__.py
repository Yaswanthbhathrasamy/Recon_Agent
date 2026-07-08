"""Provider-agnostic LLM layer for the recon engine.

Public surface:
    - ``PROVIDERS`` / ``list_providers`` / ``get_provider`` / ``build_client`` — the
      registry the TUI renders (provider -> API key -> model).
    - ``enrich_insights`` — turn a scan result into an LLM-written intelligence brief,
      with a deterministic fallback when no model is configured.
"""

from src.llm.agent import next_action
from src.llm.base import ChatResult, LLMClient, LLMError
from src.llm.enrich import enrich_insights
from src.llm.planner import plan_attacks
from src.llm.registry import (
    PROVIDERS,
    ProviderSpec,
    build_client,
    get_provider,
    list_providers,
    load_client_from_config,
)

__all__ = [
    "ChatResult",
    "LLMClient",
    "LLMError",
    "PROVIDERS",
    "ProviderSpec",
    "build_client",
    "get_provider",
    "list_providers",
    "load_client_from_config",
    "enrich_insights",
    "plan_attacks",
    "next_action",
]
