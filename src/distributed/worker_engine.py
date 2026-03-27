from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime
from datetime import timezone
from time import perf_counter
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from bs4 import BeautifulSoup

from src.core.schemas import Finding, TaskPayload, TaskResult
from src.tooling.recon_wrappers import ReconToolbox


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _normalize_target_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def _extract_host(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).netloc
    return target


class WorkerEngine:
    def __init__(self, worker_id: str = "local-worker") -> None:
        self.worker_id = worker_id
        self.tools = ReconToolbox()

    async def execute(self, task: TaskPayload) -> TaskResult:
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = perf_counter()
        try:
            handlers = {
                "subdomain_enumeration": self._subdomains,
                "dns_resolution": self._dns_resolution,
                "live_host_detection": self._live_hosts,
                "port_scan": self._port_scan,
                "technology_fingerprinting": self._tech_fingerprint,
                "url_crawling": self._url_crawling,
                "javascript_analysis": self._javascript_analysis,
                "parameter_discovery": self._parameter_discovery,
                "header_analysis": self._header_analysis,
                "sensitive_file_detection": self._sensitive_file_detection,
                "vuln_pattern_detection": self._vuln_pattern_detection,
                "finding_validation": self._finding_validation,
                "correlation_analysis": self._correlation_analysis,
                "final_intelligence": self._final_intelligence,
                # Legacy aliases
                "endpoint_discovery": self._url_crawling,
                "auth_analysis": self._header_analysis,
            }
            payload = await handlers[task.task_type](task)
            duration_ms = int((perf_counter() - t0) * 1000)
            return TaskResult(
                scan_id=task.scan_id,
                target=task.target,
                task_type=task.task_type,
                status="completed",
                severity=payload["severity"],
                summary=payload["summary"],
                data=payload["data"],
                findings=payload["findings"],
                duration_ms=duration_ms,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                worker_id=self.worker_id,
            )
        except Exception as exc:
            duration_ms = int((perf_counter() - t0) * 1000)
            return TaskResult(
                scan_id=task.scan_id,
                target=task.target,
                task_type=task.task_type,
                status="failed",
                severity="medium",
                summary=f"Task failed: {task.task_type}",
                data={},
                findings=[],
                duration_ms=duration_ms,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                worker_id=self.worker_id,
                error=str(exc),
            )

    # ── Common subdomain prefixes for brute-force discovery ────────────
    _SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "remote", "gateway",
        "api", "dev", "staging", "test", "beta", "alpha", "demo", "sandbox",
        "admin", "portal", "dashboard", "panel", "cms", "blog", "shop", "store",
        "app", "mobile", "m", "login", "auth", "sso", "id", "accounts",
        "cdn", "static", "assets", "img", "images", "media", "files", "docs",
        "db", "database", "sql", "mysql", "mongo", "postgres", "redis", "cache",
        "erp", "crm", "hr", "lms", "ems", "sis", "exam", "results", "library",
        "git", "gitlab", "github", "bitbucket", "ci", "jenkins", "jira",
        "cloud", "aws", "azure", "gcp", "s3", "backup", "bak",
        "intranet", "internal", "private", "secure", "ssl", "proxy",
        "monitor", "grafana", "kibana", "elk", "logs", "status", "health",
        "web", "web1", "web2", "server", "server1", "server2", "node1",
        "stage", "preprod", "uat", "qa", "prod", "production",
        "moodle", "elearn", "online", "exam", "placement",
        "autodiscover", "autoconfig", "cpanel", "whm", "plesk",
    ]

    async def _subdomains(self, task: TaskPayload) -> Dict:
        """Subdomain Enumeration Agent — multi-source discovery."""
        host = _extract_host(task.target)
        all_subs: set[str] = set()

        # ── Source 1: crt.sh Certificate Transparency ────────────────
        try:
            crt_resp = requests.get(
                f"https://crt.sh/?q=%.{host}&output=json",
                timeout=15,
                headers={"User-Agent": "ReconAgents/1.0"},
            )
            if crt_resp.status_code == 200:
                crt_data = crt_resp.json()
                for entry in crt_data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.endswith(f".{host}") and "*" not in name:
                            all_subs.add(name)
        except Exception:
            pass

        # ── Source 2: DNS brute-force with common prefixes ───────────
        async def _try_resolve(sub: str) -> str | None:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None, socket.getaddrinfo, sub, None, socket.AF_INET
                )
                return sub
            except (socket.gaierror, OSError):
                return None

        brute_candidates = [f"{prefix}.{host}" for prefix in self._SUBDOMAIN_WORDLIST]
        resolve_tasks = [_try_resolve(sub) for sub in brute_candidates]
        resolved = await asyncio.gather(*resolve_tasks, return_exceptions=True)
        for result in resolved:
            if isinstance(result, str) and result:
                all_subs.add(result)

        # ── Source 3: subfinder fallback (if installed) ──────────────
        try:
            subfinder_res = await self.tools.run_subfinder(host, timeout_seconds=min(task.timeout_seconds, 30))
            for sub in subfinder_res.get("subdomains", []):
                sub = sub.strip().lower()
                if sub.endswith(f".{host}"):
                    all_subs.add(sub)
        except Exception:
            pass

        # ── Normalize & validate ─────────────────────────────────────
        # Remove the base domain itself and any invalid entries
        all_subs.discard(host)
        valid_subs = sorted(
            sub for sub in all_subs
            if sub.endswith(f".{host}")
            and len(sub) <= 253
            and all(len(part) <= 63 for part in sub.split("."))
        )

        count = len(valid_subs)
        return {
            "severity": "low",
            "summary": f"Discovered {count} subdomains via CT logs + DNS brute-force",
            "data": {
                "subdomains": valid_subs,
                "count": count,
            },
            "findings": [],
        }

    async def _dns_resolution(self, task: TaskPayload) -> Dict:
        """DNS Resolution Agent — resolve subdomains to IPs."""
        host = _extract_host(task.target)
        subdomains = task.metadata.get("subdomains") or [host]
        resolved: List[Dict[str, str]] = []
        for sub in subdomains:
            try:
                infos = socket.getaddrinfo(sub, None, socket.AF_INET)
                ips = sorted({info[4][0] for info in infos})
                for ip in ips:
                    resolved.append({"host": sub, "ip": ip})
            except (socket.gaierror, OSError):
                continue
        return {
            "severity": "low",
            "summary": f"Resolved {len(resolved)} DNS records",
            "data": {"resolved": resolved, "count": len(resolved)},
            "findings": [],
        }

    async def _live_hosts(self, task: TaskPayload) -> Dict:
        target = _extract_host(task.target)
        subdomains = task.metadata.get("subdomains") or [target]
        res = await self.tools.run_httpx_live_check(subdomains, timeout_seconds=task.timeout_seconds)
        sev = "low" if res.get("count", 0) == 0 else "medium"
        return {
            "severity": sev,
            "summary": f"Detected {res.get('count', 0)} live hosts",
            "data": res,
            "findings": [],
        }

    async def _port_scan(self, task: TaskPayload) -> Dict:
        res = await self.tools.run_nmap(_extract_host(task.target), timeout_seconds=task.timeout_seconds)
        risky = [p for p in res.get("open_ports", []) if p.get("port") in {22, 3389, 3306, 5432}]
        findings = [
            Finding(
                type="Misconfiguration",
                endpoint=f"{task.target}:{item['port']}",
                title=f"Sensitive service port {item['port']} exposed",
                severity="high",
                confidence=0.98,
                state="confirmed",
                description=f"Service {item.get('service')} exposed on {item['port']}/{item.get('protocol')}",
                evidence={
                    "endpoint": f"{task.target}:{item['port']}",
                    "response_snippet": f"service={item.get('service')} protocol={item.get('protocol')}",
                },
            )
            for item in risky
        ]
        severity = "high" if risky else ("medium" if res.get("count", 0) > 0 else "low")
        return {
            "severity": severity,
            "summary": f"Open ports discovered: {res.get('count', 0)}",
            "data": res,
            "findings": findings,
        }

    async def _tech_fingerprint(self, task: TaskPayload) -> Dict:
        url = _normalize_target_url(task.target)
        response = requests.get(url, timeout=min(task.timeout_seconds, 30), verify=False)
        server = response.headers.get("Server", "unknown")
        powered_by = response.headers.get("X-Powered-By", "unknown")
        soup = BeautifulSoup(response.text, "html.parser")
        interesting_paths = []
        for path in ["/admin", "/dashboard", "/api", "/.git", "/backup"]:
            try:
                test = requests.get(f"{url.rstrip('/')}{path}", timeout=6, verify=False)
                if test.status_code in {200, 301, 302, 401, 403}:
                    interesting_paths.append(path)
            except requests.RequestException:
                continue
        js_libs = [script.get("src") for script in soup.find_all("script") if script.get("src")]
        data = {
            "server": server,
            "x_powered_by": powered_by,
            "interesting_paths": interesting_paths,
            "javascript_assets": js_libs[:20],
        }
        findings = []
        severity = "low"
        if any("admin" in path.lower() for path in interesting_paths):
            severity = "medium"
            findings.append(
                Finding(
                    type="Access Control",
                    endpoint="/admin",
                    title="Potential admin interface discovered",
                    severity="medium",
                    confidence=0.9,
                    state="confirmed",
                    description="Admin-like path is reachable and should be reviewed for access control.",
                    evidence={
                        "endpoint": "/admin",
                        "response_snippet": ",".join(interesting_paths[:5]),
                    },
                )
            )
        return {
            "severity": severity,
            "summary": f"Detected server={server}, powered_by={powered_by}",
            "data": data,
            "findings": findings,
        }

    async def _javascript_analysis(self, task: TaskPayload) -> Dict:
        url = _normalize_target_url(task.target)
        response = requests.get(url, timeout=min(task.timeout_seconds, 30), verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        js_urls = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                if src.startswith("http"):
                    js_urls.append(src)
                elif src.startswith("/"):
                    js_urls.append(url.rstrip("/") + src)

        endpoint_pattern = r"['\"](/api/[^'\"]+)['\"]"
        secret_pattern = r"(?i)(api[_-]?key|token|secret)['\"\s:=]+([A-Za-z0-9_\-]{12,})"
        endpoints = set()
        secrets = set()
        for js_url in js_urls[:10]:
            try:
                js_resp = requests.get(js_url, timeout=8, verify=False)
                content = js_resp.text
                endpoints.update(re.findall(endpoint_pattern, content))
                secrets.update(match[1] for match in re.findall(secret_pattern, content))
            except requests.RequestException:
                continue
        findings = []
        severity = "low"
        if secrets:
            severity = "high"
            findings.append(
                Finding(
                    type="Misconfiguration",
                    endpoint="javascript_asset",
                    title="Possible hardcoded secret in JavaScript",
                    severity="high",
                    confidence=0.88,
                    state="suspected",
                    description="Token-like strings detected in public JavaScript assets.",
                    evidence={
                        "endpoint": "javascript_asset",
                        "response_snippet": f"possible_secrets={len(secrets)}",
                    },
                )
            )
        elif endpoints:
            severity = "medium"
        return {
            "severity": severity,
            "summary": f"JS endpoints={len(endpoints)}, possible_secrets={len(secrets)}",
            "data": {
                "javascript_files": js_urls,
                "endpoints": sorted(endpoints),
                "secrets": sorted(secrets),
            },
            "findings": findings,
        }

    async def _parameter_discovery(self, task: TaskPayload) -> Dict:
        url = _normalize_target_url(task.target)
        baseline = requests.get(url, timeout=min(task.timeout_seconds, 20), verify=False)
        common = ["id", "user", "redirect", "token", "debug", "file", "next", "admin"]
        discovered = []
        for param in common:
            try:
                probe = requests.get(f"{url}?{param}=1", timeout=5, verify=False)
                if probe.status_code != baseline.status_code or abs(len(probe.text) - len(baseline.text)) > 40:
                    discovered.append(param)
            except requests.RequestException:
                continue
        severity = "medium" if len(discovered) >= 4 else "low"
        findings = []
        if discovered:
            findings.append(
                Finding(
                    type="Injection",
                    endpoint=url,
                    title="Potential injection-capable parameters detected",
                    severity=severity,
                    confidence=0.62,
                    state="suspected",
                    description="Response differentials suggest parameters are processed server-side and should be manually validated.",
                    evidence={
                        "endpoint": url,
                        "parameter": ",".join(discovered[:5]),
                        "response_snippet": f"active_params={len(discovered)}",
                    },
                )
            )
        return {
            "severity": severity,
            "summary": f"Potential active parameters={len(discovered)}",
            "data": {
                "parameters": discovered,
                "parameter_count": len(discovered),
            },
            "findings": findings,
        }

    async def _url_crawling(self, task: TaskPayload) -> Dict:
        """URL Crawler Agent — crawl target for all endpoints."""
        url = _normalize_target_url(task.target)
        visited: set[str] = set()
        endpoints: set[str] = set()
        to_visit = [url]
        depth = 0
        max_depth = 2

        while to_visit and depth <= max_depth:
            next_level: list[str] = []
            for page_url in to_visit:
                if page_url in visited:
                    continue
                visited.add(page_url)
                try:
                    resp = requests.get(page_url, timeout=8, verify=False)
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for anchor in soup.find_all("a"):
                        href = anchor.get("href")
                        if not href:
                            continue
                        if href.startswith("/"):
                            endpoints.add(href)
                            full = urljoin(url, href)
                            if full not in visited:
                                next_level.append(full)
                        elif href.startswith(url):
                            path = urlparse(href).path
                            if path:
                                endpoints.add(path)
                            if href not in visited:
                                next_level.append(href)
                    for form in soup.find_all("form"):
                        action = form.get("action")
                        if action and action.startswith("/"):
                            endpoints.add(action)
                except requests.RequestException:
                    continue
            to_visit = next_level[:50]
            depth += 1

        risky_keywords = ["admin", "debug", "internal", "graphql", "callback", "redirect"]
        suspicious = sorted([ep for ep in endpoints if any(k in ep.lower() for k in risky_keywords)])
        findings = []
        for ep in suspicious[:10]:
            finding_type = "Advanced" if "graphql" in ep.lower() else "Misconfiguration"
            findings.append(
                Finding(
                    type=finding_type,
                    endpoint=ep,
                    title="Sensitive endpoint pattern discovered",
                    severity="medium",
                    confidence=0.75,
                    state="suspected",
                    description="Endpoint naming suggests privileged or sensitive functionality requiring review.",
                    evidence={
                        "endpoint": ep,
                        "response_snippet": "suspicious keyword match",
                    },
                )
            )

        return {
            "severity": "medium" if suspicious else "low",
            "summary": f"Crawled {len(visited)} pages, endpoints={len(endpoints)}, suspicious={len(suspicious)}",
            "data": {
                "urls": sorted(endpoints),
                "endpoints": sorted(endpoints),
                "suspicious_endpoints": suspicious,
                "pages_crawled": len(visited),
            },
            "findings": findings,
        }

    async def _header_analysis(self, task: TaskPayload) -> Dict:
        """Header Analysis Agent — comprehensive security header checks."""
        url = _normalize_target_url(task.target)
        response = requests.get(url, timeout=min(task.timeout_seconds, 20), verify=False)
        headers = response.headers
        findings = []

        # Header checks — all classified as Misconfiguration (NOT XSS)
        header_checks = {
            "Content-Security-Policy": ("low", "Missing CSP reduces browser-side XSS mitigation."),
            "X-Frame-Options": ("low", "Missing X-Frame-Options increases clickjacking risk."),
            "Strict-Transport-Security": ("low", "Missing HSTS allows downgrade attacks."),
            "X-Content-Type-Options": ("low", "Missing nosniff allows MIME-type sniffing."),
            "Referrer-Policy": ("low", "Missing Referrer-Policy may leak sensitive URL data."),
            "Permissions-Policy": ("low", "Missing Permissions-Policy allows unrestricted browser features."),
        }

        present_headers: Dict[str, bool] = {}
        for header_name, (sev, desc) in header_checks.items():
            present = header_name in headers
            present_headers[header_name] = present
            if not present:
                findings.append(
                    Finding(
                        type="Misconfiguration",
                        endpoint=url,
                        title=f"Missing security header: {header_name}",
                        severity=sev,
                        confidence=0.95,
                        state="confirmed",
                        description=desc,
                        evidence={
                            "endpoint": url,
                            "response_snippet": f"missing header: {header_name}",
                        },
                    )
                )

        # Cookie flag analysis
        set_cookie = headers.get("Set-Cookie", "")
        has_secure_cookie = "secure" in set_cookie.lower()
        has_httponly_cookie = "httponly" in set_cookie.lower()

        if set_cookie and (not has_secure_cookie or not has_httponly_cookie):
            findings.append(
                Finding(
                    type="Auth",
                    endpoint=url,
                    title="Session cookie flags appear weak",
                    severity="medium",
                    confidence=0.8,
                    state="suspected",
                    description="Observed Set-Cookie without both Secure and HttpOnly flags.",
                    evidence={
                        "endpoint": url,
                        "response_snippet": set_cookie[:120],
                    },
                )
            )

        severity = "medium" if any(f.severity == "medium" for f in findings) else "low"

        return {
            "severity": severity,
            "summary": f"Header analysis complete, findings={len(findings)}",
            "data": {
                "security_headers": present_headers,
                "cookie_flags": {
                    "secure": has_secure_cookie,
                    "httponly": has_httponly_cookie,
                },
                "headers_raw": {k: v for k, v in headers.items()},
            },
            "findings": findings,
        }

    async def _sensitive_file_detection(self, task: TaskPayload) -> Dict:
        """Sensitive File Detection Agent — probe for exposed sensitive files/paths."""
        url = _normalize_target_url(task.target)
        probe_paths = [
            "/.git", "/.git/HEAD", "/.env", "/.htaccess", "/.svn",
            "/backup", "/config", "/wp-config.php", "/robots.txt",
            "/sitemap.xml", "/.DS_Store", "/server-status", "/phpinfo.php",
            "/web.config", "/.well-known/security.txt",
        ]
        detected: List[Dict[str, Any]] = []
        findings = []

        for path in probe_paths:
            try:
                resp = requests.get(f"{url.rstrip('/')}{path}", timeout=6, verify=False, allow_redirects=False)
                if resp.status_code in {200, 401, 403}:
                    detected.append({
                        "path": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    })
                    # Severity mapping
                    if ".git" in path or ".env" in path or ".svn" in path:
                        sev = "high"
                        desc = f"Exposed {path} may lead to source code or secret disclosure."
                    elif "backup" in path or "config" in path or "wp-config" in path:
                        sev = "high"
                        desc = f"Exposed {path} may contain sensitive configuration data."
                    elif "phpinfo" in path or "server-status" in path:
                        sev = "medium"
                        desc = f"Exposed {path} leaks server environment details."
                    else:
                        sev = "low"
                        desc = f"Detected accessible path: {path}"

                    if resp.status_code == 200 and path not in {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}:
                        findings.append(
                            Finding(
                                type="Misconfiguration",
                                endpoint=path,
                                title=f"Sensitive file exposed: {path}",
                                severity=sev,
                                confidence=0.95 if resp.status_code == 200 else 0.7,
                                state="confirmed" if resp.status_code == 200 else "suspected",
                                description=desc,
                                evidence={
                                    "endpoint": path,
                                    "response_snippet": f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                                },
                            )
                        )
            except requests.RequestException:
                continue

        top_sev = "low"
        if any(f.severity == "high" for f in findings):
            top_sev = "high"
        elif any(f.severity == "medium" for f in findings):
            top_sev = "medium"

        return {
            "severity": top_sev,
            "summary": f"Probed {len(probe_paths)} paths, detected {len(detected)} accessible",
            "data": {
                "files": [d["path"] for d in detected],
                "details": detected,
            },
            "findings": findings,
        }

    async def _vuln_pattern_detection(self, task: TaskPayload) -> Dict:
        """Vulnerability Pattern Agent — uses Nuclei for template-based scanning."""
        target = _normalize_target_url(task.target)
        res = await self.tools.run_nuclei(target, timeout_seconds=task.timeout_seconds)
        nuclei_findings = res.get("findings", [])
        findings = []
        for nf in nuclei_findings:
            sev = str(nf.get("severity", "low")).lower()
            if sev not in {"low", "medium", "high", "critical"}:
                sev = "low"
            findings.append(
                Finding(
                    type="Misconfiguration",
                    endpoint=str(nf.get("matched_at", target)),
                    title=str(nf.get("name", nf.get("template", "Unknown pattern"))),
                    severity=sev,
                    confidence=0.85,
                    state="confirmed",
                    description=f"Nuclei template {nf.get('template')} matched with severity {sev}.",
                    evidence={
                        "endpoint": str(nf.get("matched_at", "")),
                        "response_snippet": f"template={nf.get('template')}",
                    },
                )
            )
        top_sev = "low"
        if any(f.severity == "critical" for f in findings):
            top_sev = "critical"
        elif any(f.severity == "high" for f in findings):
            top_sev = "high"
        elif any(f.severity == "medium" for f in findings):
            top_sev = "medium"

        return {
            "severity": top_sev,
            "summary": f"Nuclei scan found {len(findings)} vulnerability patterns",
            "data": res,
            "findings": findings,
        }

    async def _finding_validation(self, task: TaskPayload) -> Dict:
        """Validation Agent — validate, reclassify, and prune upstream findings."""
        raw_findings: List[Dict[str, Any]] = task.metadata.get("all_findings", [])
        validated = []
        dropped = []
        parameters_exist = bool(task.metadata.get("parameters", []))

        for rf in raw_findings:
            finding_type = str(rf.get("type", ""))
            evidence = rf.get("evidence", {})
            has_payload = bool(evidence.get("payload", ""))
            has_param = bool(evidence.get("parameter", ""))
            snippet = str(evidence.get("response_snippet", ""))

            # Rule: Missing header → Misconfiguration, NOT XSS
            if "missing header" in snippet.lower():
                rf["type"] = "Misconfiguration"
                rf["severity"] = "low"
                if rf.get("state") == "confirmed":
                    rf["state"] = "confirmed"  # header absence is verifiable
                validated.append(rf)
                continue

            # Rule: No parameters → drop injection claims
            if finding_type in {"Injection", "XSS", "SSRF"} and not has_param and not parameters_exist:
                dropped.append({**rf, "drop_reason": "No parameters discovered; injection claim unsupported"})
                continue

            # Rule: No payload executed → cannot be confirmed
            if rf.get("state") == "confirmed" and not has_payload:
                rf["state"] = "suspected"

            # Rule: Weak pattern → weak_signal
            confidence = float(rf.get("confidence", 0.0))
            if confidence < 0.6 and rf.get("state") != "confirmed":
                rf["state"] = "suspected"  # weak_signal
                rf["severity"] = "low"

            validated.append(rf)

        return {
            "severity": "low",
            "summary": f"Validated {len(validated)} findings, dropped {len(dropped)}",
            "data": {
                "validated_findings": validated,
                "dropped_findings": dropped,
                "validated_count": len(validated),
                "dropped_count": len(dropped),
            },
            "findings": [],  # Validation agent doesn't produce new findings
        }

    async def _correlation_analysis(self, task: TaskPayload) -> Dict:
        """Correlation Agent — cross-signal correlation."""
        from src.intel.correlation import correlate_risks

        # Build lightweight TaskResult objects from metadata
        task_results_raw: List[Dict[str, Any]] = task.metadata.get("task_results", [])
        task_results = []
        for tr in task_results_raw:
            try:
                task_results.append(TaskResult.model_validate(tr))
            except Exception:
                continue

        insights = correlate_risks(task_results)
        return {
            "severity": "high" if any(i.severity in {"high", "critical"} for i in insights) else "medium" if insights else "low",
            "summary": f"Correlation produced {len(insights)} risk insights",
            "data": {
                "insights": [i.model_dump() for i in insights],
                "insight_count": len(insights),
            },
            "findings": [],
        }

    async def _final_intelligence(self, task: TaskPayload) -> Dict:
        """Final Intelligence Agent — produce executive summary."""
        scan_data = task.metadata.get("scan_data", {})
        subdomains = scan_data.get("recon", {}).get("subdomains", [])
        alive_hosts = scan_data.get("recon", {}).get("alive_hosts", [])
        total_findings = len(scan_data.get("preliminary_findings", []))

        # Coverage assessment
        issues: List[str] = []
        if not subdomains:
            issues.append("recon_failure")
        if not alive_hosts:
            issues.append("host_resolution_failure")
        endpoints = scan_data.get("attack_surface", {}).get("endpoints", [])
        params = scan_data.get("attack_surface", {}).get("parameters", [])
        if endpoints and not params:
            issues.append("missing_param_discovery")
        if endpoints and all(ep == "/" for ep in endpoints):
            issues.append("shallow_crawl")

        # Scan quality
        if not subdomains and not alive_hosts:
            quality = "low"
            scan_status = "failed_or_incomplete"
        elif issues:
            quality = "medium"
            scan_status = "partial"
        else:
            quality = "high"
            scan_status = "complete"

        return {
            "severity": "low",
            "summary": f"Final intelligence: status={scan_status}, quality={quality}, findings={total_findings}",
            "data": {
                "scan_status": scan_status,
                "scan_quality": quality,
                "issues": issues,
                "total_findings": total_findings,
            },
            "findings": [],
        }
