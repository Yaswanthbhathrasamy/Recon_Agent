from __future__ import annotations

from datetime import datetime
from datetime import timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]
TaskStatus = Literal["queued", "running", "completed", "failed", "cached"]
ModeType = Literal["recon", "recon_attack", "attack"]
ScanType = Literal["fast", "deep"]
FindingState = Literal["confirmed", "suspected"]
AttackCategory = Literal[
    "Injection",
    "XSS",
    "Auth",
    "Access Control",
    "Misconfiguration",
    "Web Attacks",
    "Advanced",
]
TaskType = Literal[
    "subdomain_enumeration",
    "dns_resolution",
    "live_host_detection",
    "port_scan",
    "technology_fingerprinting",
    "url_crawling",
    "javascript_analysis",
    "parameter_discovery",
    "header_analysis",
    "sensitive_file_detection",
    "vuln_pattern_detection",
    "finding_validation",
    "correlation_analysis",
    "final_intelligence",
    # Legacy aliases kept for backward compatibility
    "endpoint_discovery",
    "auth_analysis",
]


class TaskPayload(BaseModel):
    scan_id: str
    target: str
    task_type: TaskType
    mode: ModeType = "recon"
    scan_type: ScanType = "fast"
    categories: List[AttackCategory] = Field(default_factory=list)
    timeout_seconds: int = Field(default=120, ge=5, le=900)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    type: str
    endpoint: str = ""
    title: str
    severity: Severity = "low"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    state: FindingState = "suspected"
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class TaskResult(BaseModel):
    scan_id: str
    target: str
    task_type: TaskType
    status: TaskStatus
    severity: Severity
    summary: str
    data: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    duration_ms: int = 0
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    worker_id: Optional[str] = None
    error: Optional[str] = None


class RiskInsight(BaseModel):
    title: str
    severity: Severity
    rationale: str
    related_tasks: List[TaskType] = Field(default_factory=list)


class FinalScanReport(BaseModel):
    scan_id: str
    target: str
    mode: ModeType
    scan_type: ScanType
    categories: List[AttackCategory] = Field(default_factory=list)
    started_at: str
    finished_at: str
    task_results: List[TaskResult]
    insights: List[RiskInsight] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class DecisionFinding(BaseModel):
    type: str
    endpoint: str
    severity: Severity
    confidence: float
    status: FindingState
    description: str


class DecisionEngineOutput(BaseModel):
    target: str
    mode: ModeType
    subdomains: List[str] = Field(default_factory=list)
    alive_hosts: List[str] = Field(default_factory=list)
    attack_surface: List[str] = Field(default_factory=list)
    findings: List[DecisionFinding] = Field(default_factory=list)


# ── Comprehensive Output Schema ──────────────────────────────────────

FindingCategory = Literal[
    "Injection", "XSS", "Auth", "Misconfig", "SSRF",
    "Access Control", "Web Attacks", "Advanced",
]

RiskScore = Literal["low", "medium", "high", "critical"]


class LLMMeta(BaseModel):
    provider: str
    model: str


class ScanMeta(BaseModel):
    scan_id: str
    timestamp: str
    target: str
    mode: ModeType
    scan_type: ScanType
    llm: LLMMeta


class PortEntry(BaseModel):
    host: str
    port: int
    service: str = ""


class ReconSection(BaseModel):
    subdomains: List[str] = Field(default_factory=list)
    alive_hosts: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    ports: List[PortEntry] = Field(default_factory=list)


class AttackSurfaceSection(BaseModel):
    endpoints: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    headers: List[str] = Field(default_factory=list)


class FindingEvidence(BaseModel):
    endpoint: str = ""
    parameter: str = ""
    payload: str = ""
    response_snippet: str = ""


class FullFinding(BaseModel):
    id: str
    category: str
    type: str
    severity: Severity
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: FindingState = "suspected"
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    impact: str = ""
    recommendation: str = ""


class CorrelationEntry(BaseModel):
    title: str
    severity: Severity
    description: str
    related_findings: List[str] = Field(default_factory=list)


class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanSummary(BaseModel):
    total_subdomains: int = 0
    total_alive: int = 0
    total_findings: int = 0
    severity_count: SeverityCount = Field(default_factory=SeverityCount)
    risk_score: RiskScore = "low"


class FullScanOutput(BaseModel):
    meta: ScanMeta
    recon: ReconSection = Field(default_factory=ReconSection)
    attack_surface: AttackSurfaceSection = Field(default_factory=AttackSurfaceSection)
    findings: List[FullFinding] = Field(default_factory=list)
    correlation: List[CorrelationEntry] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)


class WorkerExecuteRequest(BaseModel):
    task: TaskPayload


class WorkerExecuteResponse(BaseModel):
    result: TaskResult
