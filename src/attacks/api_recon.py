"""API reconnaissance: discover REST/GraphQL surfaces from a base URL.

Finds OpenAPI/Swagger specifications, probes common API roots, and detects
GraphQL endpoints (including whether introspection is enabled). Everything here
is read-only discovery; the returned dict carries both structured data and
finding dicts for the intelligence layer.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from src.attacks.http_probe import Probe, ProbeResponse

# Well-known locations for machine-readable API specs.
_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/openapi.yaml", "/.well-known/openapi.json",
]
# Common REST roots worth probing for a live JSON API.
_API_ROOTS = ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/v1", "/v2"]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

_INTROSPECTION_QUERY = {
    "query": "query{__schema{queryType{name} types{name}}}"
}


def _finding(ftype, endpoint, severity, confidence, state, title, description, snippet=""):
    return {
        "type": ftype,
        "endpoint": endpoint,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "state": state,
        "description": description,
        "evidence": {"endpoint": endpoint, "response_snippet": str(snippet)[:200]},
    }


def _looks_like_json_api(resp: Optional[ProbeResponse]) -> bool:
    if resp is None:
        return False
    ctype = (resp.headers.get("Content-Type") or resp.headers.get("content-type") or "").lower()
    if "application/json" in ctype:
        return True
    body = (resp.text or "").strip()
    return body.startswith("{") or body.startswith("[")


def _parse_spec_endpoints(spec_text: str) -> List[str]:
    try:
        spec = json.loads(spec_text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(spec, dict):
        return []
    if "paths" not in spec:
        return []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return []
    return sorted(str(p) for p in paths.keys())


def discover_api(probe: Probe, base_url: str) -> Dict[str, Any]:
    base = base_url.rstrip("/")
    spec_urls: List[str] = []
    spec_endpoints: List[str] = []
    api_roots_live: List[str] = []
    graphql_endpoints: List[str] = []
    findings: List[Dict[str, Any]] = []

    # ── OpenAPI / Swagger specs ──────────────────────────────────────
    for path in _SPEC_PATHS:
        resp = probe.get(f"{base}{path}")
        if resp is None or resp.status != 200:
            continue
        eps = _parse_spec_endpoints(resp.text or "")
        looks_spec = eps or ('"swagger"' in (resp.text or "") or '"openapi"' in (resp.text or ""))
        if looks_spec:
            spec_urls.append(path)
            spec_endpoints.extend(eps)
            findings.append(
                _finding(
                    "Misconfiguration", path, "medium", 0.85, "confirmed",
                    "Exposed API specification",
                    f"A machine-readable API spec is publicly accessible at {path}, "
                    f"enumerating {len(eps)} endpoint(s) and expanding the attack surface.",
                    snippet=f"{len(eps)} paths",
                )
            )

    # ── Live REST roots ──────────────────────────────────────────────
    for root in _API_ROOTS:
        resp = probe.get(f"{base}{root}")
        if resp is not None and resp.status < 500 and _looks_like_json_api(resp):
            api_roots_live.append(root)

    # ── GraphQL detection + introspection ────────────────────────────
    for gpath in _GRAPHQL_PATHS:
        resp = probe.post(f"{base}{gpath}", json=_INTROSPECTION_QUERY,
                          headers={"Content-Type": "application/json"})
        if resp is None:
            continue
        body = resp.text or ""
        if "__schema" in body and resp.status == 200:
            graphql_endpoints.append(gpath)
            findings.append(
                _finding(
                    "Advanced", gpath, "high", 0.85, "confirmed",
                    "GraphQL introspection enabled",
                    f"The GraphQL endpoint {gpath} answers introspection queries, exposing the full "
                    "schema (types, queries, mutations) to unauthenticated clients.",
                    snippet="__schema returned",
                )
            )
        elif resp.status in {200, 400} and ("errors" in body and "query" in body.lower()):
            # Endpoint exists but introspection appears disabled/guarded.
            graphql_endpoints.append(gpath)

    endpoints = sorted(set(spec_endpoints))
    return {
        "spec_urls": spec_urls,
        "endpoints": endpoints,
        "api_roots": api_roots_live,
        "graphql_endpoints": sorted(set(graphql_endpoints)),
        "findings": findings,
    }
