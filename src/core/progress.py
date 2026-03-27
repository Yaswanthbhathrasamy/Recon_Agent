from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict


@dataclass
class ProgressTracker:
    total_tasks: int
    completed: int = 0
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str | None = None
    module_timings_ms: Dict[str, int] = field(default_factory=dict)

    def mark_done(self, module_name: str, duration_ms: int) -> None:
        self.completed += 1
        self.module_timings_ms[module_name] = duration_ms
        if self.completed >= self.total_tasks:
            self.finished_at = datetime.utcnow().isoformat()

    @property
    def percent(self) -> int:
        if self.total_tasks == 0:
            return 100
        return int((self.completed / self.total_tasks) * 100)
