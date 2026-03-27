from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass
from typing import List


@dataclass
class CommandResult:
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


class CommandRunner:
    async def run(self, command: List[str], timeout_seconds: int = 120) -> CommandResult:
        started = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout_b = b""
            stderr_b = f"Command timed out after {timeout_seconds}s: {shlex.join(command)}".encode("utf-8")
            exit_code = 124

        duration_ms = int((time.perf_counter() - started) * 1000)
        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
            duration_ms=duration_ms,
        )
