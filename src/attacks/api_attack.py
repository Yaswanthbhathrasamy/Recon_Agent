"""Surface-level API attack probing over discovered endpoints.

Checks that need no valid session and cause no state change:
  - Broken/absent authentication (unauthenticated access returns data)
  - BOLA / IDOR indicators (sibling object IDs return distinct data)
  - Error-based SQL injection reachable through API parameters

Templated paths from an OpenAPI spec (``/users/{id}``) are materialised with
benign sample values. Findings are dicts shaped like ``schemas.Finding``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from src.attacks.http_probe import Probe
from src.attacks.injection import _SQL_ERROR_RE

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")
_NUMERIC_TAIL_RE = re.compile(r"/(\d+)/?$")

# Endpoint keywords that make unauthenticated access notable.
_SENSITIVE_HINTS = ("user", "account", "admin", "order", "invoice", "payment", "profile", "token", "key", "secret")


def _finding(ftype, endpoint, severity, confidence, state, title, description, snippet="", param=""):
    return {
        "type": ftype,
        "endpoint": endpoint,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "state": state,
        "description": description,
        "evidence": {"endpoint": endpoint, "parameter": param, "response_snippet": str(snippet)[:200]},
    }


def _materialise(path: str) -> str:
    """Replace ``{id}`` style templates with a benign sample value."""
    return _PATH_PARAM_RE.sub("1", path)


def probe_api(probe: Probe, base_url: str, endpoints: List[str]) -> List[Dict[str, Any]]:
    base = base_url.rstrip("/")
    findings: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for raw in endpoints:
        path = raw if raw.startswith("/") else "/" + raw
        concrete = _materialise(path)
        if concrete in seen:
            continue
        seen.add(concrete)
        full = f"{base}{concrete}"

        resp = probe.get(full)
        if resp is None:
            continue
        body = resp.text or ""
        is_json = body.strip().startswith(("{", "["))

        # ── Broken/absent authentication ─────────────────────────────
        if resp.status == 200 and is_json and len(body) > 2:
            if any(h in path.lower() for h in _SENSITIVE_HINTS):
                findings.append(
                    _finding(
                        "Access Control", concrete, "high", 0.7, "suspected",
                        "Sensitive API endpoint served without authentication",
                        "A sensitive-looking API endpoint returned JSON data to an unauthenticated request; "
                        "verify whether authentication/authorization is required.",
                        snippet=f"HTTP 200, {len(body)} bytes",
                    )
                )

        # ── Error-based SQLi through API parameter ───────────────────
        if _PATH_PARAM_RE.search(path) or _NUMERIC_TAIL_RE.search(path):
            inj = probe.get(f"{base}{_PATH_PARAM_RE.sub(chr(39), path)}")  # inject a quote for {id}
            if inj is not None and _SQL_ERROR_RE.search(inj.text or ""):
                findings.append(
                    _finding(
                        "Injection", concrete, "high", 0.88, "confirmed",
                        "SQL injection via API path parameter",
                        "Injecting a quote into an API path parameter produced a database error, "
                        "indicating unsanitised input in a SQL query.",
                        snippet="SQL error in response", param="path-id",
                    )
                )

        # ── BOLA / IDOR indicator ────────────────────────────────────
        m = _NUMERIC_TAIL_RE.search(concrete)
        if m and resp.status == 200 and is_json:
            sibling = _NUMERIC_TAIL_RE.sub(f"/{int(m.group(1)) + 1}", concrete)
            sib_resp = probe.get(f"{base}{sibling}")
            if sib_resp is not None and sib_resp.status == 200 and (sib_resp.text or "") not in ("", body):
                findings.append(
                    _finding(
                        "Access Control", concrete, "medium", 0.6, "suspected",
                        "Possible BOLA/IDOR on object identifier",
                        "Two sibling object IDs both returned distinct data without authentication, a "
                        "classic Broken Object Level Authorization indicator; confirm with valid vs. "
                        "other-user credentials.",
                        snippet=f"{concrete} and {sibling} both 200 with different bodies",
                        param="object-id",
                    )
                )

    return findings
