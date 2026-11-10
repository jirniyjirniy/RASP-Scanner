"""Порт источника идентификатора прогона и времени.

Вынесено в порт, чтобы тесты были детерминированными: подставляем фиксированный
run_id и «застывшее» время вместо uuid/now().
"""

from __future__ import annotations

import abc
from datetime import datetime


class RunIdProvider(abc.ABC):
    @abc.abstractmethod
    def new_run_id(self) -> str:
        """Уникальный идентификатор прогона. Нужен, чтобы повторный запуск не падал на дубликатах."""


class Clock(abc.ABC):
    @abc.abstractmethod
    def now(self) -> datetime:
        """Текущий момент (для меток времени в отчёте)."""
