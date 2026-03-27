from __future__ import annotations

import httpx

from src.core.schemas import TaskPayload, WorkerExecuteResponse


class RemoteWorkerClient:
    def __init__(self, base_url: str, api_key: str, timeout_seconds: int = 180) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def execute_task(self, task: TaskPayload):
        headers = {"X-API-Key": self.api_key}
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/execute",
                headers=headers,
                json={"task": task.model_dump()},
            )
            response.raise_for_status()
            parsed = WorkerExecuteResponse.model_validate(response.json())
            return parsed.result
