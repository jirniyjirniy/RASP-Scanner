"""Сервисный слой: сценарии использования (use cases).

Тонкая оркестровка поверх домена и портов — то, что дёргает CLI. Ничего не знает
про httpx/файлы/Typer: получает уже собранные зависимости (UoW, config,
провайдеры) и возвращает доменный RunResult.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config import RunnerConfig
from ..domain.results import RunResult
from ..domain.scenario import Scenario
from ..ports.clock import Clock, RunIdProvider
from .engine import ScenarioRunner
from .unit_of_work import AbstractRunUnitOfWork


def run_scenarios(
    scenarios: Iterable[Scenario],
    *,
    uow: AbstractRunUnitOfWork,
    config: RunnerConfig,
    run_id_provider: RunIdProvider,
    clock: Clock,
    env: dict[str, str],
) -> RunResult:
    run_id = run_id_provider.new_run_id()   # идентификатор всего прогона (шапка отчёта)
    started = clock.now()
    results = []
    with uow:
        for scenario in scenarios:
            # каждый сценарий получает СВОЙ уникальный run_id для ${run_id}: так имена
            # создаваемых ресурсов не сталкиваются между сценариями одного прогона
            scenario_run_id = run_id_provider.new_run_id()
            runner = ScenarioRunner(uow.http, config, run_id=scenario_run_id, clock=clock, env=env)
            results.append(runner.run(scenario))
    finished = clock.now()
    return RunResult(
        run_id=run_id, target=config.target, scenarios=results,
        started_at=started, finished_at=finished,
    )
