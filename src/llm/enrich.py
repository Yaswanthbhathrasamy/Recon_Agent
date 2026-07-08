from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.llm.base import LLMClient, LLMError

_SYSTEM = (
    "You are a senior offensive-security analyst reviewing the output of an automated "
    "reconnaissance engine. You reason strictly from the evidence provided. You never "
    "invent findings, hosts, or endpoints that are not in the input. Your job is to: "
    "(1) write a concise executive summary, (2) synthesise plausible multi-step attack "
    "paths that chain the observed signals, and (3) flag any finding whose severity "
    "looks mis-rated given its evidence. Be precise and factual."
)

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "executive_summary": {"type": "string"},
        "attack_paths": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "related_signals": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "severity", "steps"],
            },
        },
        "severity_reviews": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string"},
                    "suggested_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "reason": {"type": "string"},
                },
                "required": ["finding_id", "suggested_severity", "reason"],
            },
        },
    },
    "required": ["executive_summary", "attack_paths"],
}


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort parse: handle bare JSON, ```json fences, and leading prose."""
    text = text.strip()
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        start, end = candidate.find("{"), candidate.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(candidate[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _build_prompt(context: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    recon = context.get("recon", {})
    surface = context.get("attack_surface", {})
    slim_findings = [
        {
            "id": f.get("id", ""),
            "type": f.get("type", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", 0),
            "endpoint": (f.get("evidence") or {}).get("endpoint", "") or f.get("endpoint", ""),
        }
        for f in findings
    ]
    payload = {
        "target": context.get("target", ""),
        "recon": {
            "subdomains": recon.get("subdomains", [])[:40],
            "alive_hosts": recon.get("alive_hosts", [])[:40],
            "technologies": recon.get("technologies", []),
            "open_ports": [p.get("port") if isinstance(p, dict) else p for p in recon.get("ports", [])],
        },
        "attack_surface": {
            "endpoints": surface.get("endpoints", [])[:60],
            "parameters": surface.get("parameters", [])[:60],
            "files": surface.get("files", [])[:40],
            "headers": surface.get("headers", []),
        },
        "findings": slim_findings,
    }
    return (
        "Analyse this reconnaissance result and respond with the required JSON only.\n\n"
        + json.dumps(payload, indent=2)
    )


def enrich_insights(
    client: Optional[LLMClient],
    context: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return LLM-generated intelligence for the scan.

    Always returns a dict with ``executive_summary``, ``attack_paths``,
    ``severity_reviews``, and ``engine`` keys. When ``client`` is ``None`` or the
    call fails, a deterministic summary is returned so the report is never empty.
    """
    if client is None:
        return _deterministic(context, findings, reason="no LLM configured")

    prompt = _build_prompt(context, findings)
    try:
        result = client.complete(_SYSTEM, prompt, json_schema=_SCHEMA, max_tokens=2048)
    except LLMError as exc:
        return _deterministic(context, findings, reason=f"LLM unavailable: {exc}")

    parsed = _extract_json(result.text)
    if not parsed:
        return _deterministic(context, findings, reason="LLM returned unparseable output")

    return {
        "engine": f"{result.provider}:{result.model}",
        "executive_summary": str(parsed.get("executive_summary", "")).strip(),
        "attack_paths": [ap for ap in parsed.get("attack_paths", []) if isinstance(ap, dict)],
        "severity_reviews": [sr for sr in parsed.get("severity_reviews", []) if isinstance(sr, dict)],
    }


def _deterministic(context: Dict[str, Any], findings: List[Dict[str, Any]], reason: str) -> Dict[str, Any]:
    recon = context.get("recon", {})
    n_alive = len(recon.get("alive_hosts", []))
    n_sub = len(recon.get("subdomains", []))
    highs = [f for f in findings if str(f.get("severity")) in {"high", "critical"}]
    summary = (
        f"Automated reconnaissance mapped {n_sub} subdomain(s) and {n_alive} live host(s), "
        f"surfacing {len(findings)} finding(s), {len(highs)} of high or critical severity. "
        f"(LLM narrative skipped: {reason}.)"
    )
    return {
        "engine": "deterministic",
        "executive_summary": summary,
        "attack_paths": [],
        "severity_reviews": [],
    }
