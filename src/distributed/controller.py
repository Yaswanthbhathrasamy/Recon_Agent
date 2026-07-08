from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from typing import List, Optional, Tuple

from src.core.cache import ReconCache, build_cache
from src.core.progress import ProgressTracker
from src.core.schemas import (
    AgentStep,
    AttackCategory,
    FinalScanReport,
    ModeType,
    ScanType,
    TaskPayload,
    TaskResult,
)
from src.distributed.remote_client import RemoteWorkerClient
from src.distributed.task_queue import TaskQueue, build_task_queue
from src.distributed.worker_engine import WorkerEngine
from src.intel.correlation import correlate_risks
from src.llm import load_client_from_config, next_action, plan_attacks


@dataclass
class _RunCtx:
    """Parameters shared across a single scan's task executions."""

    scan_id: str
    target: str
    mode: ModeType
    categories: List[AttackCategory]
    scan_type: ScanType
    timeout_seconds: int
    progress: ProgressTracker


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

        Execution has three phases:
          1. Recon      — parallel passive/active discovery.
          2. Attack     — sequential active testing, focused by the LLM planner.
          3. Post       — validation, correlation, and final intelligence.
        """
        if mode == "recon":
            return [
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
                # Attack-surface recon (needed to feed active testing)
                "url_crawling",
                "javascript_analysis",
                "parameter_discovery",
                "vuln_pattern_detection",
                # Active testing
                "api_discovery",
                "sqli_testing",
                "xss_testing",
                "api_attack_surface",
                # Post-processing
                "finding_validation",
                "correlation_analysis",
                "final_intelligence",
            ]
        # recon_attack – full pipeline
        return [
            # Recon
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
            # Active testing (api_discovery before api_attack_surface)
            "api_discovery",
            "sqli_testing",
            "xss_testing",
            "api_attack_surface",
            # Post-processing
            "finding_validation",
            "correlation_analysis",
            "final_intelligence",
        ]

    # Active-testing tasks run after recon so they can be LLM-focused.
    _ATTACK_TASKS = {"api_discovery", "sqli_testing", "xss_testing", "api_attack_surface"}
    # Post-processing tasks run last, over recon + attack results.
    _POST_TASKS = {"finding_validation", "correlation_analysis", "final_intelligence"}

    def _aggregate_meta(self, results: List[TaskResult]) -> dict:
        """Fold task results into the metadata bundle downstream agents consume."""
        all_findings_raw = [f.model_dump() for r in results for f in r.findings]
        parameters: List[str] = []
        subdomains: List[str] = []
        endpoints_all: List[str] = []
        api_endpoints: List[str] = []

        meta: dict = {
            "all_findings": all_findings_raw,
            "parameters": [],
            "subdomains": [],
            "endpoints": [],
            "api_endpoints": [],
            "task_results": [r.model_dump() for r in results],
            "scan_data": {
                "recon": {"subdomains": [], "alive_hosts": [], "technologies": [], "ports": []},
                "attack_surface": {"endpoints": [], "parameters": [], "files": []},
                "preliminary_findings": all_findings_raw,
            },
        }

        for r in results:
            if r.task_type == "parameter_discovery":
                parameters = r.data.get("parameters", [])
            elif r.task_type == "subdomain_enumeration":
                subdomains = r.data.get("subdomains", [])
            elif r.task_type == "live_host_detection":
                hosts = [h["url"] for h in r.data.get("live_hosts", []) if isinstance(h, dict) and h.get("url")]
                meta["scan_data"]["recon"]["alive_hosts"] = hosts
            elif r.task_type == "technology_fingerprinting":
                server = r.data.get("server", "")
                meta["scan_data"]["recon"]["technologies"] = [server] if server and server != "unknown" else []
            elif r.task_type == "port_scan":
                meta["scan_data"]["recon"]["ports"] = r.data.get("open_ports", [])
            elif r.task_type in ("url_crawling", "endpoint_discovery"):
                eps = r.data.get("endpoints", [])
                meta["scan_data"]["attack_surface"]["endpoints"] = eps
                endpoints_all += eps
            elif r.task_type == "javascript_analysis":
                endpoints_all += r.data.get("endpoints", [])
            elif r.task_type == "sensitive_file_detection":
                meta["scan_data"]["attack_surface"]["files"] = r.data.get("files", [])
            elif r.task_type == "api_discovery":
                api_endpoints += r.data.get("endpoints", [])
                endpoints_all += r.data.get("endpoints", [])

        meta["parameters"] = parameters
        meta["subdomains"] = subdomains
        meta["scan_data"]["recon"]["subdomains"] = subdomains
        meta["scan_data"]["attack_surface"]["parameters"] = parameters
        meta["endpoints"] = sorted({str(e) for e in endpoints_all})
        meta["api_endpoints"] = sorted({str(e) for e in api_endpoints})
        return meta

    async def run_scan(
        self,
        target: str,
        scan_id: str | None = None,
        mode: ModeType = "recon",
        categories: List[AttackCategory] | None = None,
        scan_type: ScanType = "fast",
        agentic: bool = False,
    ) -> tuple[FinalScanReport, ProgressTracker]:
        scan_id = scan_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        categories = categories or []

        task_types = self._task_plan(mode)
        progress = ProgressTracker(total_tasks=len(task_types))
        timeout_seconds = 120 if scan_type == "fast" else 300
        ctx = _RunCtx(scan_id, target, mode, categories, scan_type, timeout_seconds, progress)

        # Autonomous mode needs an LLM to drive; without one, fall back to the
        # deterministic phased pipeline.
        use_agentic = agentic and load_client_from_config() is not None
        if use_agentic:
            all_results, agent_trace = await self._run_agentic(ctx, task_types)
        else:
            all_results = await self._run_phased(ctx, task_types)
            agent_trace = []

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
            agentic=use_agentic,
            agent_trace=agent_trace,
        )
        return report, progress

    def _payload(self, ctx: _RunCtx, task_type: str, meta: dict | None = None) -> TaskPayload:
        return TaskPayload(
            scan_id=ctx.scan_id,
            target=ctx.target,
            task_type=task_type,
            mode=ctx.mode,
            scan_type=ctx.scan_type,
            categories=ctx.categories,
            timeout_seconds=ctx.timeout_seconds,
            metadata=meta or {},
        )

    async def _execute(self, ctx: _RunCtx, task_type: str, meta: dict | None = None) -> TaskResult:
        await self.queue.enqueue(self._payload(ctx, task_type, meta))
        result = await self._consume_and_execute(ctx.target)
        ctx.progress.mark_done(result.task_type, result.duration_ms)
        return result

    async def _run_phased(self, ctx: _RunCtx, task_types: List[str]) -> List[TaskResult]:
        """Deterministic recon -> attack -> post pipeline (no LLM required)."""
        recon = [t for t in task_types if t not in self._ATTACK_TASKS and t not in self._POST_TASKS]
        attack = [t for t in task_types if t in self._ATTACK_TASKS]
        post = [t for t in task_types if t in self._POST_TASKS]

        # Phase 1: recon (parallel)
        for t in recon:
            await self.queue.enqueue(self._payload(ctx, t))
        recon_results: List[TaskResult] = list(
            await asyncio.gather(*[self._consume_and_execute(ctx.target) for _ in recon])
        )
        for r in recon_results:
            ctx.progress.mark_done(r.task_type, r.duration_ms)
        all_results: List[TaskResult] = list(recon_results)

        # Phase 2: attacks (sequential, LLM-focused)
        if attack:
            meta = self._aggregate_meta(recon_results)
            meta["attack_focus"] = self._plan_focus(ctx.target, meta)
            for t in attack:
                res = await self._execute(ctx, t, meta)
                all_results.append(res)
                if res.task_type == "api_discovery":
                    meta["api_endpoints"] = res.data.get("endpoints", [])

        # Phase 3: post-processing
        if post:
            meta = self._aggregate_meta(all_results)
            for t in post:
                all_results.append(await self._execute(ctx, t, meta))
        return all_results

    def _observation(self, results: List[TaskResult], remaining: List[str]) -> dict:
        """A compact snapshot of the assessment the agent reasons over each turn."""
        meta = self._aggregate_meta(results)
        recon = meta["scan_data"]["recon"]
        sev: dict = {}
        for f in meta["all_findings"]:
            s = str(f.get("severity", "low"))
            sev[s] = sev.get(s, 0) + 1
        return {
            "tools_completed": [r.task_type for r in results],
            "subdomains_found": len(meta.get("subdomains", [])),
            "alive_hosts": len(recon.get("alive_hosts", [])),
            "open_ports": [p.get("port") if isinstance(p, dict) else p for p in recon.get("ports", [])],
            "technologies": recon.get("technologies", []),
            "endpoints_found": len(meta.get("endpoints", [])),
            "parameters_found": meta.get("parameters", []),
            "api_endpoints_found": meta.get("api_endpoints", []),
            "findings_total": len(meta["all_findings"]),
            "findings_by_severity": sev,
        }

    async def _run_agentic(self, ctx: _RunCtx, task_types: List[str]) -> Tuple[List[TaskResult], List[AgentStep]]:
        """Autonomous loop: the LLM chooses the next tool(s) until it finishes.

        Post-processing (validation/correlation/final intelligence) always runs at
        the end regardless of the agent's choices — it's bookkeeping, not a tool.
        """
        client = load_client_from_config()
        post = [t for t in task_types if t in self._POST_TASKS]
        remaining = [t for t in task_types if t not in self._POST_TASKS]

        all_results: List[TaskResult] = []
        trace: List[AgentStep] = []
        meta: dict = {}
        max_steps = len(remaining) + 3
        step = 0

        while remaining and step < max_steps:
            step += 1
            meta = self._aggregate_meta(all_results)
            observation = self._observation(all_results, remaining)
            decision = next_action(client, ctx.target, remaining, observation) if client else None

            if decision is None:
                # Degrade gracefully: make forward progress one tool at a time.
                thought, reason, chosen = "", "no LLM decision; running next planned tool", remaining[:1]
            elif decision["action"] == "finish":
                trace.append(AgentStep(step=step, thought=decision["thought"], action="finish",
                                       tasks=[], reason=decision["reason"]))
                break
            else:
                thought, reason = decision["thought"], decision["reason"]
                chosen = decision["tasks"] or remaining[:1]

            if any(t in self._ATTACK_TASKS for t in chosen):
                meta["attack_focus"] = self._plan_focus(ctx.target, meta)

            executed: List[str] = []
            for t in chosen:
                if t not in remaining:
                    continue
                res = await self._execute(ctx, t, meta)
                all_results.append(res)
                remaining.remove(t)
                executed.append(t)
                if res.task_type == "api_discovery":
                    meta["api_endpoints"] = res.data.get("endpoints", [])

            trace.append(AgentStep(step=step, thought=thought, action="run", tasks=executed, reason=reason))

        # Post-processing always runs.
        if post:
            meta = self._aggregate_meta(all_results)
            for t in post:
                all_results.append(await self._execute(ctx, t, meta))
        return all_results, trace

    def _plan_focus(self, target: str, meta: dict) -> dict:
        """Ask the configured LLM which params/endpoints to focus active testing on.

        Never raises: any failure (no config, no key, bad response) degrades to an
        empty focus, which the workers read as "test everything discovered".
        """
        try:
            client = load_client_from_config()
            recon = meta.get("scan_data", {}).get("recon", {})
            context = {
                "target": target,
                "parameters": meta.get("parameters", []),
                "endpoints": meta.get("endpoints", []),
                "technologies": recon.get("technologies", []),
                "ports": [p.get("port") if isinstance(p, dict) else p for p in recon.get("ports", [])],
            }
            return plan_attacks(client, context)
        except Exception:
            return {"params": [], "endpoints": [], "rationale": ""}

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

