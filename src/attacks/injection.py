"""Surface-level active injection testing: SQLi, reflected XSS, open redirect.

Non-destructive by design — payloads probe for *detectable behaviour* (error
strings, boolean differentials, unencoded reflection, redirect targets) rather
than attempting exploitation or data exfiltration. Findings are returned as plain
dicts shaped like ``src.core.schemas.Finding`` so the worker can wrap them.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.attacks.http_probe import Probe, ProbeResponse

# DBMS error signatures — presence with a quote payload (and absence in baseline)
# is strong evidence of an unsanitised SQL sink.
_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ora-\d{5}",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlite3?::",
    r"sqlite_error",
    r"syntax error at or near",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"supplied argument is not a valid mysql",
]
_SQL_ERROR_RE = re.compile("|".join(_SQL_ERRORS), re.IGNORECASE)

_XSS_MARKER = "recon0xss"
# A payload that only executes/renders if reflected without HTML-encoding.
_XSS_PAYLOAD = f"\"'><svg/onload=alert({_XSS_MARKER})>"

_REDIRECT_PARAMS = {"redirect", "url", "next", "return", "returnurl", "dest", "destination", "continue", "r", "u"}
_REDIRECT_CANARY = "https://recon-canary.example"


def _finding(
    ftype: str,
    endpoint: str,
    param: str,
    severity: str,
    confidence: float,
    state: str,
    title: str,
    description: str,
    payload: str = "",
    snippet: str = "",
) -> Dict[str, Any]:
    return {
        "type": ftype,
        "endpoint": endpoint,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "state": state,
        "description": description,
        "evidence": {
            "endpoint": endpoint,
            "parameter": param,
            "payload": payload,
            "response_snippet": snippet[:200],
        },
    }


def _baseline(probe: Probe, url: str, param: str) -> Optional[ProbeResponse]:
    return probe.get(url, params={param: "1"})


def test_sqli(probe: Probe, url: str, params: List[str]) -> List[Dict[str, Any]]:
    """Error-based and boolean-based SQLi detection for each parameter."""
    findings: List[Dict[str, Any]] = []
    for param in params:
        base = _baseline(probe, url, param)
        if base is None:
            continue
        base_has_error = bool(_SQL_ERROR_RE.search(base.text or ""))

        # ── Error-based ──────────────────────────────────────────────
        err_resp = probe.get(url, params={param: "1'\""})
        if err_resp is not None and not base_has_error and _SQL_ERROR_RE.search(err_resp.text or ""):
            match = _SQL_ERROR_RE.search(err_resp.text or "")
            findings.append(
                _finding(
                    "Injection", url, param, "high", 0.9, "confirmed",
                    "SQL injection (error-based)",
                    "Injecting a quote produced a database error absent from the baseline response, "
                    "indicating unsanitised input reaching a SQL query.",
                    payload="1'\"", snippet=match.group(0) if match else "",
                )
            )
            continue  # already strong evidence; skip boolean probe for this param

        # ── Boolean-based ────────────────────────────────────────────
        true_resp = probe.get(url, params={param: "1 AND 1=1"})
        false_resp = probe.get(url, params={param: "1 AND 1=2"})
        if true_resp is not None and false_resp is not None:
            true_len, false_len = len(true_resp.text or ""), len(false_resp.text or "")
            same_as_true = abs(true_len - len(base.text or "")) < 40
            differs_false = abs(true_len - false_len) > 60 and (true_resp.status == base.status)
            if same_as_true and differs_false:
                findings.append(
                    _finding(
                        "Injection", url, param, "high", 0.72, "suspected",
                        "SQL injection (boolean-based)",
                        "TRUE and FALSE SQL conditions produced materially different responses while the "
                        "TRUE case matched the baseline, suggesting a boolean-based SQL injection point.",
                        payload="1 AND 1=1 / 1 AND 1=2",
                        snippet=f"len(true)={true_len} len(false)={false_len} len(base)={len(base.text or '')}",
                    )
                )
    return findings


def test_xss(probe: Probe, url: str, params: List[str]) -> List[Dict[str, Any]]:
    """Reflected XSS detection — payload reflected unencoded into the response."""
    findings: List[Dict[str, Any]] = []
    for param in params:
        resp = probe.get(url, params={param: _XSS_PAYLOAD})
        if resp is None:
            continue
        body = resp.text or ""
        # Reflected verbatim (unencoded) -> executable
        if _XSS_PAYLOAD in body:
            findings.append(
                _finding(
                    "XSS", url, param, "high", 0.85, "suspected",
                    "Reflected XSS (unencoded reflection)",
                    "The injected script payload was reflected into the response without HTML-encoding, "
                    "indicating a reflected cross-site scripting sink.",
                    payload=_XSS_PAYLOAD, snippet="payload reflected verbatim",
                )
            )
        elif _XSS_MARKER in body and ("&lt;" in body or "&gt;" in body):
            # Marker present but angle brackets encoded -> reflected-but-safe (informational)
            findings.append(
                _finding(
                    "XSS", url, param, "low", 0.5, "suspected",
                    "Input reflection (encoded)",
                    "User input is reflected into the response but HTML metacharacters appear encoded; "
                    "review context-specific sinks (attributes, JS, URLs) for XSS.",
                    payload=_XSS_PAYLOAD, snippet="marker reflected, brackets encoded",
                )
            )
    return findings


def test_open_redirect(probe: Probe, url: str, params: List[str]) -> List[Dict[str, Any]]:
    """Open-redirect detection on redirect-like parameters."""
    findings: List[Dict[str, Any]] = []
    for param in params:
        if param.lower() not in _REDIRECT_PARAMS:
            continue
        resp = probe.get(url, params={param: _REDIRECT_CANARY}, allow_redirects=False)
        if resp is None:
            continue
        location = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if resp.status in {301, 302, 303, 307, 308} and _REDIRECT_CANARY in location:
            findings.append(
                _finding(
                    "Web Attacks", url, param, "medium", 0.8, "suspected",
                    "Open redirect",
                    "A user-controlled parameter is reflected into the Location header of a redirect, "
                    "allowing redirection to an attacker-controlled destination.",
                    payload=_REDIRECT_CANARY, snippet=f"Location: {location[:120]}",
                )
            )
    return findings


def run_surface_attacks(
    probe: Probe,
    url: str,
    params: List[str],
    *,
    categories: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Run the enabled surface-attack classes and merge their findings."""
    cats = set(categories or ["Injection", "XSS", "Web Attacks"])
    out: List[Dict[str, Any]] = []
    if not params:
        return out
    if "Injection" in cats:
        out += test_sqli(probe, url, params)
    if "XSS" in cats:
        out += test_xss(probe, url, params)
    if "Web Attacks" in cats or "Injection" in cats:
        out += test_open_redirect(probe, url, params)
    return out
