from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from datetime import timezone
from typing import List, Optional

from src.core.cache import ReconCache, build_cache
from src.core.progress import ProgressTracker
from src.core.schemas import AttackCategory, FinalScanReport, ModeType, ScanType, TaskPayload, TaskResult
from src.distributed.remote_client import RemoteWorkerClient
from src.distributed.task_queue import TaskQueue, build_task_queue
from src.distributed.worker_engine import WorkerEngine
from src.intel.correlation import correlate_risks


class ReconController:
    def __init__(
        self,
        queue: TaskQueue | None = None,
        cache: ReconCache | None = None,
        remote_worker_url: Optional[str] = None,
        remote_api_key: Optional[str] = None,
    ) -> None:
        self.queue = queue or build_task_queue()
        self.cache = cache or build_cache()
        self.local_worker = WorkerEngine(worker_id="local-controller-worker")
        self.remote_client = (
            RemoteWorkerClient(remote_worker_url, remote_api_key)
            if remote_worker_url and remote_api_key
            else None
        )

    def _task_plan(self, mode: ModeType) -> List[str]:
        """Return the ordered list of task types for the given mode.

        Phase-1 tasks run in parallel.
        Phase-2 tasks (validation, correlation, final_intelligence) run after
        phase-1 completes and receive aggregated metadata.
        """
        if mode == "recon":
            return [
                # Phase 1 – parallel recon
                "subdomain_enumeration",
                "dns_resolution",
                "live_host_detection",
                "port_scan",
                "technology_fingerprinting",
                "url_crawling",
                "header_analysis",
                "sensitive_file_detection",
            ]
        if mode == "attack":
            return [
                # Phase 1 – parallel attack-surface analysis
                "javascript_analysis",
                "parameter_discovery",
                "vuln_pattern_detection",
                # Phase 2 – sequential post-processing
                "finding_validation",
                "correlation_analysis",
                "final_intelligence",
            ]
        # recon_attack – full 14-agent pipeline
        return [
            # Phase 1 – parallel recon + attack surface
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
            # Phase 2 – sequential post-processing
            "finding_validation",
            "correlation_analysis",
            "final_intelligence",
        ]

    # List of task types that must run AFTER phase-1 completes.
    _PHASE2_TASKS = {"finding_validation", "correlation_analysis", "final_intelligence"}

    async def run_scan(
        self,
        target: str,
        scan_id: str | None = None,
        mode: ModeType = "recon",
        categories: List[AttackCategory] | None = None,
        scan_type: ScanType = "fast",
    ) -> tuple[FinalScanReport, ProgressTracker]:
        scan_id = scan_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        categories = categories or []

        task_types = self._task_plan(mode)
        progress = ProgressTracker(total_tasks=len(task_types))
        timeout_seconds = 120 if scan_type == "fast" else 300

        # Split into Phase 1 (parallel) and Phase 2 (sequential, needs metadata)
        phase1_types = [t for t in task_types if t not in self._PHASE2_TASKS]
        phase2_types = [t for t in task_types if t in self._PHASE2_TASKS]

        # ── Phase 1: parallel execution ──────────────────────────────────
        phase1_payloads = [
            TaskPayload(
                scan_id=scan_id,
                target=target,
                task_type=task_type,
                mode=mode,
                scan_type=scan_type,
                categories=categories,
                timeout_seconds=timeout_seconds,
            )
            for task_type in phase1_types
        ]

        for payload in phase1_payloads:
            await self.queue.enqueue(payload)

        result_tasks = [self._consume_and_execute(target) for _ in phase1_payloads]
        phase1_results: List[TaskResult] = list(await asyncio.gather(*result_tasks))

        for item in phase1_results:
            progress.mark_done(item.task_type, item.duration_ms)

        # ── Phase 2: sequential execution with metadata piping ───────────
        all_results = list(phase1_results)

        if phase2_types:
            # Aggregate metadata from Phase 1 for downstream agents
            all_findings_raw = []
            for r in phase1_results:
                for f in r.findings:
                    all_findings_raw.append(f.model_dump())
            
            parameters = []
            subdomains = []
            for r in phase1_results:
                if r.task_type == "parameter_discovery":
                    parameters = r.data.get("parameters", [])
                if r.task_type == "subdomain_enumeration":
                    subdomains = r.data.get("subdomains", [])

            aggregated_meta = {
                "all_findings": all_findings_raw,
                "parameters": parameters,
                "subdomains": subdomains,
                "task_results": [r.model_dump() for r in phase1_results],
                "scan_data": {
                    "recon": {
                        "subdomains": subdomains,
                        "alive_hosts": [],
                        "technologies": [],
                        "ports": [],
                    },
                    "attack_surface": {
                        "endpoints": [],
                        "parameters": parameters,
                        "files": [],
                    },
                    "preliminary_findings": all_findings_raw,
                },
            }

            # Fill in aggregated_meta.scan_data from Phase-1 results
            for r in phase1_results:
                if r.task_type == "live_host_detection":
                    hosts = []
                    for h in r.data.get("live_hosts", []):
                        if isinstance(h, dict) and h.get("url"):
                            hosts.append(h["url"])
                    aggregated_meta["scan_data"]["recon"]["alive_hosts"] = hosts
                if r.task_type == "technology_fingerprinting":
                    techs = []
                    server = r.data.get("server", "")
                    if server and server != "unknown":
                        techs.append(server)
                    aggregated_meta["scan_data"]["recon"]["technologies"] = techs
                if r.task_type == "port_scan":
                    aggregated_meta["scan_data"]["recon"]["ports"] = r.data.get("open_ports", [])
                if r.task_type == "url_crawling":
                    aggregated_meta["scan_data"]["attack_surface"]["endpoints"] = r.data.get("endpoints", [])
                if r.task_type == "sensitive_file_detection":
                    aggregated_meta["scan_data"]["attack_surface"]["files"] = r.data.get("files", [])

            for task_type in phase2_types:
                payload = TaskPayload(
                    scan_id=scan_id,
                    target=target,
                    task_type=task_type,
                    mode=mode,
                    scan_type=scan_type,
                    categories=categories,
                    timeout_seconds=timeout_seconds,
                    metadata=aggregated_meta,
                )
                await self.queue.enqueue(payload)
                result = await self._consume_and_execute(target)
                all_results.append(result)
                progress.mark_done(result.task_type, result.duration_ms)

        insights = correlate_risks(all_results)
        errors = [r.error for r in all_results if r.error]
        report = FinalScanReport(
            scan_id=scan_id,
            target=target,
            mode=mode,
            scan_type=scan_type,
            categories=categories,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            task_results=all_results,
            insights=insights,
            errors=errors,
        )
        return report, progress

    async def _consume_and_execute(self, target: str) -> TaskResult:
        task = await self.queue.dequeue(timeout_seconds=2)
        if task is None:
            raise RuntimeError("Task dequeue timed out unexpectedly")

        cache_key = self.cache.make_key(
            target,
            task.task_type,
            task.mode,
            task.scan_type,
            ",".join(sorted(task.categories)),
        )
        cached = await self.cache.get(cache_key)
        if cached:
            cached_result = TaskResult.model_validate(cached)
            cached_result.status = "cached"
            return cached_result

        if self.remote_client:
            result = await self.remote_client.execute_task(task)
        else:
            result = await self.local_worker.execute(task)

        await self.cache.set(cache_key, result.model_dump(), ttl_seconds=1800)
        return result

