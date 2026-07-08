"""Autonomous agent decision loop (provider-agnostic).

Instead of a fixed pipeline, the model is placed in a perceive -> decide -> act
loop: each turn it sees what has been discovered so far and the tools still
available, then chooses which tool(s) to run next (with reasoning) or declares the
assessment complete. Because it works through the uniform ``LLMClient.complete``
JSON interface, the same loop runs on Claude, GPT, Gemini, Ollama, etc. — no
provider-specific tool-calling required.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.llm.base import LLMClient, LLMError

# One-line capability descriptions the agent reasons over.
TOOL_DESCRIPTIONS: Dict[str, str] = {
    "subdomain_enumeration": "Discover subdomains (CT logs, DNS brute-force).",
    "dns_resolution": "Resolve discovered hosts to IP addresses.",
    "live_host_detection": "Probe which hosts are alive over HTTP/HTTPS.",
    "port_scan": "Scan for open ports and services.",
    "technology_fingerprinting": "Identify server software and tech stack.",
    "url_crawling": "Crawl the site to enumerate endpoints and forms.",
    "javascript_analysis": "Parse JS for API endpoints and leaked secrets.",
    "parameter_discovery": "Find hidden GET/POST parameters (injection candidates).",
    "header_analysis": "Check security headers and cookie flags.",
    "sensitive_file_detection": "Probe for exposed files (.git, .env, backups).",
    "vuln_pattern_detection": "Run Nuclei template matching for known patterns.",
    "api_discovery": "Find OpenAPI/Swagger specs and GraphQL endpoints.",
    "sqli_testing": "Actively test parameters for SQL injection.",
    "xss_testing": "Actively test parameters for reflected XSS and open redirect.",
    "api_attack_surface": "Probe APIs for broken auth, BOLA/IDOR, and injection.",
}

_SYSTEM = (
    "You are an autonomous offensive-security agent running an AUTHORISED assessment "
    "of a single target. You operate in a loop: you are shown the current findings and "
    "the tools still available, and you decide the next tool(s) to run. Reason like an "
    "operator: establish the attack surface with reconnaissance BEFORE running active "
    "tests, run parameter/endpoint discovery before injection testing, and run API "
    "discovery before API attacks. Choose the fewest tools that advance the assessment; "
    "you may pick several when they are independent. Declare 'finish' only when the "
    "remaining tools would add no value given what you have found. Only choose tools from "
    "the provided 'available' list."
)

_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "thought": {"type": "string"},
        "action": {"type": "string", "enum": ["run", "finish"]},
        "tasks": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
    "required": ["action", "reason"],
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


def next_action(
    client: LLMClient,
    target: str,
    available: List[str],
    observation: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Ask the agent for its next move.

    Returns ``{"thought", "action": "run"|"finish", "tasks": [...], "reason"}`` with
    ``tasks`` constrained to ``available``. Returns ``None`` if the model could not be
    reached or produced unusable output, so the caller can fall back deterministically.
    """
    if not available:
        return {"thought": "", "action": "finish", "tasks": [], "reason": "no tools remaining"}

    tool_menu = {t: TOOL_DESCRIPTIONS.get(t, "") for t in available}
    prompt = (
        f"Target: {target}\n\n"
        f"Findings and surface discovered so far:\n{json.dumps(observation, indent=2)}\n\n"
        f"Tools still available (choose only from these):\n{json.dumps(tool_menu, indent=2)}\n\n"
        "Decide the next action as JSON."
    )
    try:
        result = client.complete(_SYSTEM, prompt, json_schema=_SCHEMA, max_tokens=1024)
    except LLMError:
        return None

    parsed = _extract_json(result.text)
    if not parsed or parsed.get("action") not in {"run", "finish"}:
        return None

    avail = set(available)
    tasks = [t for t in parsed.get("tasks", []) if t in avail]
    return {
        "thought": str(parsed.get("thought", "")).strip(),
        "action": parsed.get("action"),
        "tasks": tasks,
        "reason": str(parsed.get("reason", "")).strip(),
    }
