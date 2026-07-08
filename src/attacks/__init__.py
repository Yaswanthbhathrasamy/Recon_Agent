"""Active surface-level attack and API testing modules.

All testers drive the target through a bounded ``Probe`` (request budget + delay)
and take an injected ``fetch`` callable, so they run non-destructively in
production and are unit-testable without a network.
"""

from src.attacks.api_attack import probe_api
from src.attacks.api_recon import discover_api
from src.attacks.http_probe import Probe, ProbeResponse, requests_fetch
from src.attacks.injection import (
    run_surface_attacks,
    test_open_redirect,
    test_sqli,
    test_xss,
)

__all__ = [
    "Probe",
    "ProbeResponse",
    "requests_fetch",
    "run_surface_attacks",
    "test_sqli",
    "test_xss",
    "test_open_redirect",
    "discover_api",
    "probe_api",
]
