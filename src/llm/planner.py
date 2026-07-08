"""LLM-driven attack planning — the agentic layer.

After recon, the model is shown the discovered surface and decides where the
active testing should focus: which parameters and endpoints are most likely to be
exploitable, and why. This narrows active testing to high-value targets instead of
fuzzing everything. When no LLM is configured (or the call fails) the planner
returns an empty focus, which the workers treat as "test everything discovered".
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.llm.base import LLMClient, LLMError

_SYSTEM = (
    "You are an offensive-security operator planning the active-testing phase of an "
    "authorised assessment. Given a map of the discovered attack surface, select the "
    "parameters and endpoints most worth actively testing for SQL injection, XSS, and "
    "broken access control, and briefly justify the plan. Only choose from the values "
    "provided. Prefer parameters and endpoints whose names imply database lookups, "
    "identifiers, redirects, file access, or privileged functionality."
)

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "params": {"type": "array", "items": {"type": "string"}},
        "endpoints": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
    "required": ["params", "endpoints"],
}


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    text = (text or "").strip()
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        s, e = candidate.find("{"), candidate.rfind("}")
        if 0 <= s < e:
            try:
                return json.loads(candidate[s : e + 1])
            except json.JSONDecodeError:
                return None
    return None


def plan_attacks(client: Optional[LLMClient], context: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``{"params": [...], "endpoints": [...], "rationale": str}``.

    Values are constrained to those present in ``context`` so the plan can never
    invent a target the recon phase didn't observe.
    """
    known_params: List[str] = [str(p) for p in context.get("parameters", [])]
    known_endpoints: List[str] = [str(e) for e in context.get("endpoints", [])]

    empty = {"params": [], "endpoints": [], "rationale": ""}
    if client is None or (not known_params and not known_endpoints):
        return empty

    prompt = "Attack surface:\n" + json.dumps(
        {
            "target": context.get("target", ""),
            "technologies": context.get("technologies", []),
            "open_ports": context.get("ports", []),
            "parameters": known_params[:60],
            "endpoints": known_endpoints[:80],
        },
        indent=2,
    ) + "\n\nReturn the focus plan as JSON."

    try:
        result = client.complete(_SYSTEM, prompt, json_schema=_SCHEMA, max_tokens=1024)
    except LLMError:
        return empty

    parsed = _extract_json(result.text)
    if not parsed:
        return empty

    # Constrain to observed values — the model may not introduce new targets.
    param_set, ep_set = set(known_params), set(known_endpoints)
    return {
        "params": [p for p in parsed.get("params", []) if p in param_set][:20],
        "endpoints": [e for e in parsed.get("endpoints", []) if e in ep_set][:20],
        "rationale": str(parsed.get("rationale", "")).strip(),
    }
