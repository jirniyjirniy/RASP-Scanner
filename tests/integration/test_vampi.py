"""Интеграционные тесты против живого VAmPI.

Запускаются, только если стенд доступен по TARGET_URL (иначе skip). Проверяют,
что каждый поставляемый сценарий действительно находит уязвимость на VAmPI.

    poetry/uv: сначала `docker run -d -p 5001:5000 erev0s/vampi` (см. scripts/vampi.sh),
    затем `pytest -m integration`.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from rasp_scanner.bootstrap import bootstrap
from rasp_scanner.domain.enums import Verdict
from rasp_scanner.service_layer.services import run_scenarios

pytestmark = pytest.mark.integration

TARGET = os.environ.get("TARGET_URL", "http://localhost:5001")
SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "scenarios"

# VAmPI сид-учётки → в env для сценария idor-books (${env.USER_A_NAME} и т.д.)
VAMPI_ENV = {
    "USER_A_NAME": "name1", "USER_A_PASS": "pass1",
    "USER_B_NAME": "name2", "USER_B_PASS": "pass2",
}

EXPECTED_VULNERABLE = [
    "idor-books",
    "mass-assignment-admin",
    "broken-auth-debug-leak",
    "workflow-bypass-password",
    "privilege-escalation-delete",
]


@pytest.fixture(scope="module")
def vampi_ready() -> str:
    try:
        httpx.get(f"{TARGET}/", timeout=2.0)
        httpx.get(f"{TARGET}/createdb", timeout=5.0)   # чистый сид
    except Exception:
        pytest.skip(f"VAmPI недоступен по {TARGET} — интеграционные тесты пропущены")
    return TARGET


@pytest.fixture(scope="module")
def run_result(vampi_ready):
    app = bootstrap(scenarios_dir=SCENARIOS_DIR, target=vampi_ready, env=VAMPI_ENV)
    scenarios = app.repository.list()
    return run_scenarios(
        scenarios, uow=app.uow, config=app.config,
        run_id_provider=app.run_id_provider, clock=app.clock, env=app.env,
    )


def test_overall_verdict_is_vulnerable(run_result):
    assert run_result.verdict is Verdict.VULNERABLE
    assert run_result.summary["error"] == 0


@pytest.mark.parametrize("scenario_id", EXPECTED_VULNERABLE)
def test_each_scenario_is_vulnerable(run_result, scenario_id):
    by_id = {s.id: s for s in run_result.scenarios}
    result = by_id[scenario_id]
    assert result.verdict is Verdict.VULNERABLE, (
        f"{scenario_id}: ожидалась VULNERABLE, получено {result.verdict.value}; "
        f"error={result.error}"
    )
