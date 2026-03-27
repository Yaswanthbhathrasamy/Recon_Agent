from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from src.tooling.command_runner import CommandRunner, CommandResult


class ReconToolbox:
    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner()

    async def run_subfinder(self, target: str, timeout_seconds: int = 120) -> Dict[str, Any]:
        result = await self.runner.run(["subfinder", "-silent", "-d", target], timeout_seconds=timeout_seconds)
        subdomains = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
        return {
            "subdomains": subdomains,
            "count": len(subdomains),
            "tool_meta": self._meta(result),
        }

    async def run_httpx_live_check(self, hosts: List[str], timeout_seconds: int = 120) -> Dict[str, Any]:
        if not hosts:
            return {"live_hosts": [], "count": 0, "tool_meta": {"skipped": True}}
        joined = "\n".join(hosts)
        cmd = ["bash", "-lc", "httpx -silent -json"]
        result = await self._run_with_stdin(cmd, joined, timeout_seconds)
        live_hosts: List[Dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                live_hosts.append(
                    {
                        "url": parsed.get("url"),
                        "status_code": parsed.get("status_code"),
                        "webserver": parsed.get("webserver"),
                        "title": parsed.get("title"),
                    }
                )
            except json.JSONDecodeError:
                continue
        return {
            "live_hosts": live_hosts,
            "count": len(live_hosts),
            "tool_meta": self._meta(result),
        }

    async def run_nmap(self, target: str, timeout_seconds: int = 180) -> Dict[str, Any]:
        result = await self.runner.run(["nmap", "-sV", "-F", target], timeout_seconds=timeout_seconds)
        open_ports: List[Dict[str, Any]] = []
        for line in result.stdout.splitlines():
            match = re.search(r"^(\d+)/(tcp|udp)\s+open\s+([\w\-\?]+)", line.strip())
            if match:
                open_ports.append(
                    {
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                    }
                )
        return {
            "open_ports": open_ports,
            "count": len(open_ports),
            "tool_meta": self._meta(result),
        }

    async def run_nuclei(self, target: str, timeout_seconds: int = 240) -> Dict[str, Any]:
        result = await self.runner.run(["nuclei", "-u", target, "-jsonl", "-silent"], timeout_seconds=timeout_seconds)
        findings: List[Dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = parsed.get("info", {})
            findings.append(
                {
                    "template": parsed.get("template-id"),
                    "name": info.get("name"),
                    "severity": str(info.get("severity", "low")).lower(),
                    "matched_at": parsed.get("matched-at"),
                }
            )
        return {
            "findings": findings,
            "count": len(findings),
            "tool_meta": self._meta(result),
        }

    async def _run_with_stdin(self, command: List[str], stdin_text: str, timeout_seconds: int) -> CommandResult:
        import asyncio
        import time

        started = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin_text.encode("utf-8")), timeout=timeout_seconds
            )
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout_b = b""
            stderr_b = f"Command timed out after {timeout_seconds}s".encode("utf-8")
            exit_code = 124

        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _meta(self, result: CommandResult) -> Dict[str, Any]:
        return {
            "command": result.command,
            "exit_code": result.exit_code,
            "stderr": result.stderr.strip(),
            "duration_ms": result.duration_ms,
        }
