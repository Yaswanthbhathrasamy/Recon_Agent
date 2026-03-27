from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from src.core.schemas import (
    AttackSurfaceSection,
    CorrelationEntry,
    FindingEvidence,
    FullFinding,
    FullScanOutput,
    LLMMeta,
    PortEntry,
    ReconSection,
    ScanMeta,
    ScanSummary,
    SeverityCount,
)


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_IMPACT_MAP = {
    "Injection": "May allow unauthorized data access or command execution on the server.",
    "XSS": "May allow execution of malicious scripts in user browsers.",
    "Auth": "May allow session hijacking or authentication bypass.",
    "Access Control": "May allow unauthorized access to restricted resources.",
    "Misconfiguration": "May expose sensitive information or widen the attack surface.",
    "Web Attacks": "May enable client-side attacks such as clickjacking or CSRF.",
    "Advanced": "May lead to server-side exploitation or business logic abuse.",
    "SSRF": "May allow internal network access from the target server.",
}

_RECOMMENDATION_MAP = {
    "Injection": "Implement parameterized queries and strict input validation.",
    "XSS": "Deploy Content-Security-Policy headers and sanitize all user input.",
    "Auth": "Enforce secure session management with HttpOnly/Secure cookie flags.",
    "Access Control": "Implement proper authorization checks and restrict admin endpoints.",
    "Misconfiguration": "Remove sensitive files from public access and harden server configuration.",
    "Web Attacks": "Add X-Frame-Options, CSRF tokens, and validate redirect targets.",
    "Advanced": "Conduct manual testing for business logic flaws and SSRF vectors.",
    "SSRF": "Restrict outbound requests and validate all user-supplied URLs.",
}


def _severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _finding_id(category: str, endpoint: str, desc: str) -> str:
    raw = f"{category}:{endpoint}:{desc}".lower().encode()
    return f"FIND-{hashlib.sha256(raw).hexdigest()[:8].upper()}"


def _normalize_category(raw_type: str) -> str:
    mapping = {
        "injection": "Injection",
        "xss": "XSS",
        "auth": "Auth",
        "access control": "Access Control",
        "misconfiguration": "Misconfig",
        "misconfig": "Misconfig",
        "web attacks": "Web Attacks",
        "advanced": "Advanced",
        "ssrf": "SSRF",
    }
    return mapping.get(raw_type.lower(), raw_type)


def _normalize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": str(raw.get("type", "Unknown")),
        "endpoint": str(raw.get("endpoint", "")).strip(),
        "severity": str(raw.get("severity", "low")).lower(),
        "confidence": float(raw.get("confidence", 0.0)),
        "status": str(raw.get("status", raw.get("state", "suspected"))).lower(),
        "description": str(raw.get("description", "")).strip(),
        "evidence": raw.get("evidence", {}),
    }


def _dedupe_and_prune(preliminary_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for raw in preliminary_findings:
        f = _normalize_finding(raw)
        key = (f["type"].lower(), f["endpoint"].lower(), f["description"].lower())
        if key not in merged:
            merged[key] = f
            continue

        existing = merged[key]
        existing["confidence"] = max(existing["confidence"], f["confidence"])
        existing["severity"] = _severity_max(existing["severity"], f["severity"])
        if existing["status"] != "confirmed" and f["status"] == "confirmed":
            existing["status"] = "confirmed"

    output: List[Dict[str, Any]] = []
    for finding in merged.values():
        is_weak = finding["confidence"] < 0.55 and finding["status"] != "confirmed"
        if not is_weak:
            output.append(finding)
    return output


def _build_correlations(
    scan_data: Dict[str, Any],
    finding_ids: List[str],
) -> List[CorrelationEntry]:
    attack_surface = [str(x).lower() for x in scan_data.get("attack_surface", {}).get("endpoints", [])]
    attack_surface += [str(x).lower() for x in scan_data.get("attack_surface", {}).get("files", [])]
    ports = scan_data.get("recon", {}).get("ports", [])

    has_admin = any("/admin" in x or "admin" in x for x in attack_surface)
    risky_ports = {22, 3306, 3389, 5432, 6379, 27017}
    open_risky = [p for p in ports if isinstance(p, dict) and p.get("port") in risky_ports]

    prelim = scan_data.get("preliminary_findings", [])
    has_auth_weakness = any(
        str(item.get("type", "")).lower() in {"auth", "access control", "web attacks"}
        for item in prelim
    )

    correlations: List[CorrelationEntry] = []

    if has_admin and open_risky:
        sev = "critical" if has_auth_weakness else "high"
        correlations.append(CorrelationEntry(
            title="Admin surface with exposed sensitive services",
            severity=sev,
            description="Admin endpoint combined with sensitive open ports increases exploitation potential.",
            related_findings=finding_ids[:5],
        ))

    sensitive = [x for x in attack_surface if any(k in x for k in [".env", "/.git", "debug", "graphql", "backup"])]
    if sensitive:
        correlations.append(CorrelationEntry(
            title="Sensitive file/path exposure",
            severity="high" if len(sensitive) > 1 else "medium",
            description=f"Detected {len(sensitive)} sensitive path(s) in the attack surface.",
            related_findings=finding_ids[:3],
        ))

    techs = scan_data.get("recon", {}).get("technologies", [])
    if any("php" in str(t).lower() for t in techs) and open_risky:
        correlations.append(CorrelationEntry(
            title="Legacy technology with exposed services",
            severity="medium",
            description="PHP-based stack with sensitive open ports may increase injection risk.",
            related_findings=finding_ids[:3],
        ))

    return correlations


def _compute_risk_score(severity_count: SeverityCount) -> str:
    if severity_count.critical > 0:
        return "critical"
    if severity_count.high >= 2:
        return "high"
    if severity_count.high >= 1 or severity_count.medium >= 3:
        return "high"
    if severity_count.medium >= 1:
        return "medium"
    return "low"


def finalize_security_insights(
    scan_data: Dict[str, Any],
    errors: List[str] | None = None,
    scan_id: str = "",
    target: str = "",
    mode: str = "recon",
    scan_type: str = "fast",
    provider: str = "openai",
    model: str = "gpt-4o",
) -> Dict[str, Any]:
    errors = errors or []

    # ── Build meta ────────────────────────────────────────────────────
    meta = ScanMeta(
        scan_id=scan_id or f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        target=target,
        mode=mode,
        scan_type=scan_type,
        llm=LLMMeta(provider=provider, model=model),
    )

    # ── Build recon section ───────────────────────────────────────────
    recon_data = scan_data.get("recon", {})
    port_entries = []
    for p in recon_data.get("ports", []):
        if isinstance(p, dict):
            port_entries.append(PortEntry(
                host=str(p.get("host", target)),
                port=int(p.get("port", 0)),
                service=str(p.get("service", "")),
            ))
        elif isinstance(p, int):
            port_entries.append(PortEntry(host=target, port=p, service=""))

    recon = ReconSection(
        subdomains=recon_data.get("subdomains", []),
        alive_hosts=recon_data.get("alive_hosts", []),
        technologies=recon_data.get("technologies", []),
        ports=port_entries,
    )

    # ── Build attack surface ──────────────────────────────────────────
    as_data = scan_data.get("attack_surface", {})
    attack_surface = AttackSurfaceSection(
        endpoints=as_data.get("endpoints", []),
        parameters=as_data.get("parameters", []),
        files=as_data.get("files", []),
        headers=as_data.get("headers", []),
    )

    # ── Build findings ────────────────────────────────────────────────
    preliminary = scan_data.get("preliminary_findings", [])
    cleaned = _dedupe_and_prune(preliminary)
    cleaned.sort(
        key=lambda x: (SEVERITY_ORDER.get(x["severity"], 0), x["confidence"]),
        reverse=True,
    )

    findings: List[FullFinding] = []
    for f in cleaned:
        category = _normalize_category(f["type"])
        evidence_raw = f.get("evidence", {})
        evidence = FindingEvidence(
            endpoint=str(evidence_raw.get("endpoint", f.get("endpoint", ""))),
            parameter=str(evidence_raw.get("parameter", evidence_raw.get("parameters", ""))),
            payload=str(evidence_raw.get("payload", "")),
            response_snippet=str(evidence_raw.get("response_snippet", "")),
        )
        fid = _finding_id(category, f["endpoint"], f["description"])
        findings.append(FullFinding(
            id=fid,
            category=category,
            type=f["type"],
            severity=f["severity"],
            confidence=f["confidence"],
            status=f["status"],
            evidence=evidence,
            impact=_IMPACT_MAP.get(f["type"], _IMPACT_MAP.get(category, "")),
            recommendation=_RECOMMENDATION_MAP.get(f["type"], _RECOMMENDATION_MAP.get(category, "")),
        ))

    # ── Build correlations ────────────────────────────────────────────
    finding_ids = [f.id for f in findings]
    correlations = _build_correlations(scan_data, finding_ids)

    # Add correlated findings that don't duplicate existing ones
    for corr in correlations:
        corr_id = _finding_id("Correlated", corr.title, corr.description)
        if not any(f.id == corr_id for f in findings):
            findings.append(FullFinding(
                id=corr_id,
                category="Misconfig",
                type="Correlated Risk",
                severity=corr.severity,
                confidence=0.9,
                status="suspected",
                evidence=FindingEvidence(endpoint="multi-signal"),
                impact=corr.description,
                recommendation="Investigate correlated signals and apply layered defense.",
            ))

    # ── Build summary ─────────────────────────────────────────────────
    sev_count = SeverityCount(
        critical=sum(1 for f in findings if f.severity == "critical"),
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
    )

    summary = ScanSummary(
        total_subdomains=len(recon.subdomains),
        total_alive=len(recon.alive_hosts),
        total_findings=len(findings),
        severity_count=sev_count,
        risk_score=_compute_risk_score(sev_count),
    )

    # ── Assemble output ───────────────────────────────────────────────
    output = FullScanOutput(
        meta=meta,
        recon=recon,
        attack_surface=attack_surface,
        findings=findings,
        correlation=correlations,
        summary=summary,
    )
    return output.model_dump()
