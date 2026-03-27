from __future__ import annotations

from typing import List

from src.core.schemas import RiskInsight, TaskResult


def correlate_risks(results: List[TaskResult]) -> List[RiskInsight]:
    by_task = {r.task_type: r for r in results}
    insights: List[RiskInsight] = []

    port_scan = by_task.get("port_scan")
    tech = by_task.get("technology_fingerprinting")
    js = by_task.get("javascript_analysis")
    params = by_task.get("parameter_discovery")
    auth = by_task.get("auth_analysis") or by_task.get("header_analysis")
    files = by_task.get("sensitive_file_detection")

    admin_present = False
    if tech:
        dirs = tech.data.get("interesting_paths", [])
        admin_present = any("admin" in str(path).lower() for path in dirs)

    high_risk_port_exposed = False
    if port_scan:
        risky_ports = {22, 3306, 3389, 5432, 6379, 27017}
        for item in port_scan.data.get("open_ports", []):
            if item.get("port") in risky_ports:
                high_risk_port_exposed = True
                break

    weak_auth_signal = False
    if auth:
        for finding in auth.findings:
            if (
                finding.type in {"Auth", "Access Control", "Web Attacks", "Misconfiguration"}
                and finding.severity in {"medium", "high", "critical"}
            ):
                weak_auth_signal = True
                break

    if admin_present and high_risk_port_exposed and weak_auth_signal:
        insights.append(
            RiskInsight(
                title="Correlated privileged exposure with weak access posture",
                severity="critical",
                rationale="Admin exposure plus privileged open services and weak auth/session signals indicate high-impact compromise potential.",
                related_tasks=["technology_fingerprinting", "port_scan", "header_analysis"],
            )
        )

    elif admin_present and high_risk_port_exposed:
        insights.append(
            RiskInsight(
                title="Admin surface with privileged service exposure",
                severity="high",
                rationale="Admin-like endpoint combined with sensitive open service ports increases exploitation likelihood.",
                related_tasks=["technology_fingerprinting", "port_scan"],
            )
        )

    if js and js.data.get("secrets"):
        insights.append(
            RiskInsight(
                title="Potential client-side secret exposure",
                severity="high",
                rationale="JavaScript analysis detected token/key-like material that may allow unauthorized access.",
                related_tasks=["javascript_analysis"],
            )
        )

    if params and params.data.get("parameter_count", 0) > 8:
        insights.append(
            RiskInsight(
                title="Large parameter attack surface",
                severity="medium",
                rationale="High number of discovered parameters suggests broad input vectors for injection and logic abuse.",
                related_tasks=["parameter_discovery"],
            )
        )

    # New: Sensitive file exposure correlation
    if files:
        exposed = files.data.get("files", [])
        git_exposed = any(".git" in str(f) for f in exposed)
        env_exposed = any(".env" in str(f) for f in exposed)
        if git_exposed:
            sev = "critical" if high_risk_port_exposed else "high"
            insights.append(
                RiskInsight(
                    title="Git repository exposed — potential source code leak",
                    severity=sev,
                    rationale="Exposed .git directory may allow full source code extraction, credential harvesting, and internal path disclosure.",
                    related_tasks=["sensitive_file_detection", "port_scan"],
                )
            )
        if env_exposed:
            insights.append(
                RiskInsight(
                    title="Environment file exposed — potential credential leak",
                    severity="critical",
                    rationale="Exposed .env file likely contains database credentials, API keys, and secret tokens.",
                    related_tasks=["sensitive_file_detection"],
                )
            )

    return insights

