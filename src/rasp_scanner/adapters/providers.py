"""Боевые источники run_id и времени."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..ports.clock import Clock, RunIdProvider


class UuidRunIdProvider(RunIdProvider):
    def new_run_id(self) -> str:
        # короткий, но уникальный: хватает, чтобы разводить имена в стенде между прогонами
        return uuid.uuid4().hex[:12]


class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)
