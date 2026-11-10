"""Composition root.

Единственное место, где боевые адаптеры собираются вместе и подставляются в
порты. Весь остальной код зависит от абстракций; меняем реализацию — правим
только здесь. Тесты собирают свой граф с поддельными адаптерами, минуя bootstrap.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .adapters.httpx_client import HttpxClient
from .adapters.providers import SystemClock, UuidRunIdProvider
from .adapters.reporters import ConsoleReporter, HtmlReporter, JsonReporter
from .adapters.yaml_repository import YamlScenarioRepository
from .config import RunnerConfig, load_config
from .ports.clock import Clock, RunIdProvider
from .ports.reporting import AbstractReporter
from .ports.repository import AbstractScenarioRepository
from .service_layer.unit_of_work import AbstractRunUnitOfWork, RunUnitOfWork


@dataclass(slots=True)
class AppContext:
    config: RunnerConfig
    repository: AbstractScenarioRepository
    uow: AbstractRunUnitOfWork
    run_id_provider: RunIdProvider
    clock: Clock
    env: dict[str, str]


def bootstrap(
    *,
    scenarios_dir: str | Path,
    config_path: str | Path | None = None,
    target: str | None = None,
    env: dict[str, str] | None = None,
) -> AppContext:
    config = load_config(config_path, target=target)
    repository = YamlScenarioRepository(scenarios_dir)
    uow = RunUnitOfWork(
        lambda: HttpxClient(timeout=config.timeout, verify_tls=config.verify_tls)
    )
    return AppContext(
        config=config,
        repository=repository,
        uow=uow,
        run_id_provider=UuidRunIdProvider(),
        clock=SystemClock(),
        env=dict(env if env is not None else os.environ),
    )


_REPORTERS: dict[str, type[AbstractReporter]] = {
    "console": ConsoleReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
}


def make_reporter(fmt: str) -> AbstractReporter:
    try:
        return _REPORTERS[fmt]()
    except KeyError:
        raise ValueError(f"неизвестный формат отчёта {fmt!r}; доступны: {', '.join(_REPORTERS)}")
