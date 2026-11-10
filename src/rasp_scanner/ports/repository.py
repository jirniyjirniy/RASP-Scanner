"""Порт репозитория сценариев.

Абстрагирует ИСТОЧНИК сценариев (каталог YAML сегодня, БД/реестр завтра) от
движка и CLI. Отдаёт уже провалидированные доменные объекты Scenario.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator

from ..domain.scenario import Scenario


class AbstractScenarioRepository(abc.ABC):
    @abc.abstractmethod
    def list(self) -> list[Scenario]:
        """Все доступные сценарии (отсортированы стабильно)."""

    @abc.abstractmethod
    def get(self, scenario_id: str) -> Scenario:
        """Один сценарий по id. Нет такого → ScenarioNotFoundError."""

    def filter(self, *, ids: list[str] | None = None, tags: list[str] | None = None) -> Iterator[Scenario]:
        """Выборка по id и/или тегам (пересечение тегов). Без фильтров → все."""
        for scenario in self.list():
            if ids is not None and scenario.id not in ids:
                continue
            if tags is not None and not (set(tags) & set(scenario.tags)):
                continue
            yield scenario
