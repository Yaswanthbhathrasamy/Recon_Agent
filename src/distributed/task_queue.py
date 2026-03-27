from __future__ import annotations

import asyncio
import json
import os
from typing import Optional

from src.core.schemas import TaskPayload


class TaskQueue:
    async def enqueue(self, task: TaskPayload) -> None:
        raise NotImplementedError

    async def dequeue(self, timeout_seconds: int = 1) -> Optional[TaskPayload]:
        raise NotImplementedError


class InMemoryTaskQueue(TaskQueue):
    def __init__(self) -> None:
        self._q: asyncio.Queue[TaskPayload] = asyncio.Queue()

    async def enqueue(self, task: TaskPayload) -> None:
        await self._q.put(task)

    async def dequeue(self, timeout_seconds: int = 1) -> Optional[TaskPayload]:
        try:
            return await asyncio.wait_for(self._q.get(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            return None


class RedisTaskQueue(TaskQueue):
    def __init__(self, redis_url: str, queue_name: str = "recon:tasks") -> None:
        import redis.asyncio as redis

        self._client = redis.from_url(redis_url, decode_responses=True)
        self._queue_name = queue_name

    async def enqueue(self, task: TaskPayload) -> None:
        await self._client.rpush(self._queue_name, task.model_dump_json())

    async def dequeue(self, timeout_seconds: int = 1) -> Optional[TaskPayload]:
        result = await self._client.blpop(self._queue_name, timeout=timeout_seconds)
        if not result:
            return None
        _, payload = result
        return TaskPayload.model_validate(json.loads(payload))


def build_task_queue() -> TaskQueue:
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        return RedisTaskQueue(redis_url)
    return InMemoryTaskQueue()
