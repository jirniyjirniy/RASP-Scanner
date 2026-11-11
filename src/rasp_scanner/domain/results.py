"""Результаты выполнения (что движок произвёл и что увидит отчёт).

Чистые dataclass-снимки: по ним строятся JSON/HTML-отчёты и вердикт. Домен их
создаёт, адаптеры-репортеры — только читают.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .enums import Severity, StepOutcome, StepType, Verdict
from .http import RequestBody


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Одна проверка внутри expect/secure_if (status, json-путь, body, var)."""

    kind: str
    passed: bool
    message: str


@dataclass(frozen=True, slots=True)
class RequestSnapshot:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    body: RequestBody | None = None
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResponseSnapshot:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class StepResult:
    name: str
    type: StepType
    outcome: StepOutcome
    as_role: str | None = None
    request: RequestSnapshot | None = None
    response: ResponseSnapshot | None = None
    checks: list[CheckResult] = field(default_factory=list)
    saved: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    secure_if_hit: bool = False
    duration_ms: float = 0.0

    @property
    def failed_checks(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


@dataclass(slots=True)
class ScenarioResult:
    id: str
    name: str
    severity: Severity
    wstg: str
    verdict: Verdict
    description: str | None = None
    remediation: str | None = None
    tags: list[str] = field(default_factory=list)
    steps: list[StepResult] = field(default_factory=list)
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def duration_ms(self) -> float:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds() * 1000
        return 0.0


@dataclass(slots=True)
class RunResult:
    run_id: str
    target: str
    scenarios: list[ScenarioResult] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def verdict(self) -> Verdict:
        """Худший вердикт по всем сценариям (пустой прогон → SECURE)."""
        worst = Verdict.SECURE
        for s in self.scenarios:
            if s.verdict.rank > worst.rank:
                worst = s.verdict
        return worst

    @property
    def summary(self) -> dict[str, int]:
        counts = {v.value: 0 for v in Verdict}
        for s in self.scenarios:
            counts[s.verdict.value] += 1
        counts["total"] = len(self.scenarios)
        return counts
