from __future__ import annotations

import json
import os
import time
from hashlib import sha256
from typing import Any, Optional


class ReconCache:
    def make_key(self, *parts: str) -> str:
        digest = sha256("::".join(parts).encode("utf-8")).hexdigest()
        return f"recon:{digest}"

    async def get(self, key: str) -> Optional[dict]:
        raise NotImplementedError

    async def set(self, key: str, value: dict, ttl_seconds: int = 3600) -> None:
        raise NotImplementedError


class InMemoryCache(ReconCache):
    def __init__(self) -> None:
        self._store: dict[str, tuple[float, dict]] = {}

    async def get(self, key: str) -> Optional[dict]:
        item = self._store.get(key)
        if not item:
            return None
        expires_at, value = item
        if time.time() > expires_at:
            self._store.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: dict, ttl_seconds: int = 3600) -> None:
        self._store[key] = (time.time() + ttl_seconds, value)


class RedisCache(ReconCache):
    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as redis

        self._client = redis.from_url(redis_url, decode_responses=True)

    async def get(self, key: str) -> Optional[dict]:
        raw = await self._client.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    async def set(self, key: str, value: dict, ttl_seconds: int = 3600) -> None:
        await self._client.set(key, json.dumps(value), ex=ttl_seconds)


def build_cache() -> ReconCache:
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        return RedisCache(redis_url)
    return InMemoryCache()
