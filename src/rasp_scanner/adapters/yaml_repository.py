"""Адаптер репозитория: сценарии из каталога YAML-файлов.

Один файл = один сценарий. Загружает, валидирует через Pydantic (ошибка формата
сразу укажет файл) и кеширует. Отдаёт доменные Scenario.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from ..domain.errors import ScannerError, ScenarioNotFoundError
from ..domain.scenario import Scenario
from ..ports.repository import AbstractScenarioRepository


class ScenarioLoadError(ScannerError):
    """Файл сценария не читается/не проходит валидацию."""


class YamlScenarioRepository(AbstractScenarioRepository):
    def __init__(self, directory: str | Path, *, pattern: str = "*.yaml") -> None:
        self._dir = Path(directory)
        self._pattern = pattern
        self._cache: dict[str, Scenario] | None = None

    def _load_all(self) -> dict[str, Scenario]:
        if self._cache is not None:
            return self._cache
        if not self._dir.is_dir():
            raise ScenarioLoadError(f"каталог сценариев не найден: {self._dir}")

        scenarios: dict[str, Scenario] = {}
        for file in sorted(self._dir.glob(self._pattern)):
            scenario = self._load_file(file)
            if scenario.id in scenarios:
                raise ScenarioLoadError(
                    f"дублируется id сценария {scenario.id!r}: {file.name} и уже загруженный"
                )
            scenarios[scenario.id] = scenario
        self._cache = scenarios
        return scenarios

    @staticmethod
    def _load_file(file: Path) -> Scenario:
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ScenarioLoadError(f"{file.name}: невалидный YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ScenarioLoadError(f"{file.name}: ожидался YAML-словарь сценария")
        try:
            return Scenario.model_validate(data)
        except ValidationError as exc:
            raise ScenarioLoadError(f"{file.name}: сценарий не прошёл валидацию:\n{exc}") from exc

    def list(self) -> list[Scenario]:
        return list(self._load_all().values())

    def get(self, scenario_id: str) -> Scenario:
        scenarios = self._load_all()
        if scenario_id not in scenarios:
            raise ScenarioNotFoundError(
                f"сценарий {scenario_id!r} не найден. Есть: {', '.join(sorted(scenarios)) or '—'}"
            )
        return scenarios[scenario_id]
