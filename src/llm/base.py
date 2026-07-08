from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class LLMError(Exception):
    """Raised when an LLM backend cannot fulfil a request.

    The message is safe to surface to the user; it never contains the API key.
    """


@dataclass
class ChatResult:
    text: str
    provider: str
    model: str
    raw: Dict[str, Any] = field(default_factory=dict)


class LLMClient:
    """Uniform interface every provider adapter implements.

    Adapters are constructed with a resolved model and (optionally) an API key.
    ``complete`` sends a single system+user turn and returns the model's text.
    When ``json_schema`` is provided the adapter asks the model for JSON and the
    caller is responsible for parsing; adapters make a best effort to constrain
    the output but callers must still tolerate malformed JSON.
    """

    provider: str = "base"

    def __init__(self, model: str, api_key: Optional[str] = None, **options: Any) -> None:
        self.model = model
        self.api_key = api_key
        self.options = options

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        json_schema: Optional[Dict[str, Any]] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
    ) -> ChatResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def health_check(self) -> None:
        """Raise ``LLMError`` with an actionable message if the client is unusable.

        The default is a lightweight, offline check; adapters may override to make
        a cheap network probe.
        """
        raise NotImplementedError
