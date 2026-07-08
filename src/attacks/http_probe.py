"""Shared, bounded HTTP probing primitive for active surface testing.

Every active module (SQLi, XSS, API attacks) drives the target through a single
``Probe`` so we can enforce one safety budget across the whole scan: a hard cap on
total requests and an optional inter-request delay. The actual transport is a
``fetch`` callable, which keeps these modules unit-testable without a network — the
worker injects a ``requests``-backed fetch; tests inject a fake.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


@dataclass
class ProbeResponse:
    status: int
    text: str
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    url: str = ""


# fetch(method, url, params=..., data=..., json=..., headers=..., allow_redirects=...)
Fetch = Callable[..., Optional[ProbeResponse]]


@dataclass
class Probe:
    """A request-budgeted wrapper around a ``fetch`` callable."""

    fetch: Fetch
    max_requests: int = 400
    delay: float = 0.0
    sent: int = 0
    budget_hit: bool = False

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json: Any = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[ProbeResponse]:
        if self.sent >= self.max_requests:
            self.budget_hit = True
            return None
        self.sent += 1
        if self.delay:
            time.sleep(self.delay)
        try:
            return self.fetch(
                method,
                url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                allow_redirects=allow_redirects,
            )
        except Exception:
            return None

    def get(self, url: str, **kwargs: Any) -> Optional[ProbeResponse]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[ProbeResponse]:
        return self.request("POST", url, **kwargs)


def requests_fetch(timeout: int = 8) -> Fetch:
    """Build a ``fetch`` backed by the ``requests`` library (lazy import)."""
    import requests

    def _fetch(
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json: Any = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[ProbeResponse]:
        try:
            resp = requests.request(
                method,
                url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException:
            return None
        return ProbeResponse(
            status=resp.status_code,
            text=resp.text,
            headers={k: v for k, v in resp.headers.items()},
            elapsed=resp.elapsed.total_seconds() if resp.elapsed else 0.0,
            url=resp.url,
        )

    return _fetch
