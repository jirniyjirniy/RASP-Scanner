"""Тесты движка через поддельный HttpClient — без сети.

Сценарии собираются из dict (заодно проверяется валидация моделей) и гоняются
целиком. Проверяем вердикты, ленивый логин, save→use, secure_if, остановку.
"""

import pytest

from rasp_scanner.config import RunnerConfig
from rasp_scanner.domain.enums import StepOutcome, Verdict
from rasp_scanner.domain.scenario import Scenario
from rasp_scanner.service_layer.engine import ScenarioRunner

from _doubles import FakeHttpClient, FixedClock, Router, make_response

CONFIG = RunnerConfig(target="http://test")


def run(scenario_dict, handler, *, env=None):
    scenario = Scenario.model_validate(scenario_dict)
    fake = FakeHttpClient(handler)
    runner = ScenarioRunner(fake, CONFIG, run_id="RID", clock=FixedClock(), env=env or {})
    return runner.run(scenario), fake


def login_route(router: Router, token="TOK"):
    return router.add("POST", "/users/v1/login", make_response(200, json={"auth_token": token}))


# ── базовые вердикты ────────────────────────────────────────────────────────
def test_attack_vulnerable_when_safe_expectation_fails():
    router = Router()
    login_route(router)
    router.add("GET", "/secret", make_response(200, json={"secret": "leak"}))
    scenario = {
        "id": "s", "name": "n", "severity": "high", "wstg": "WSTG-ATHZ-04",
        "roles": {"u": {"username": "a", "password": "p"}},
        "steps": [{
            "name": "read", "type": "attack", "as": "u",
            "request": {"method": "GET", "path": "/secret"},
            "expect": {"status": [401, 403]},
        }],
    }
    result, fake = run(scenario, router)
    assert result.verdict is Verdict.VULNERABLE
    # токен был подставлен в запрос к /secret
    secret_req = fake.sent_to("GET", "/secret")[0]
    assert secret_req.headers["Authorization"] == "Bearer TOK"


def test_attack_secure_when_server_defends():
    router = Router()
    login_route(router)
    router.add("GET", "/secret", make_response(403, json={"detail": "forbidden"}))
    scenario = {
        "id": "s", "name": "n", "severity": "high", "wstg": "WSTG-ATHZ-04",
        "roles": {"u": {"username": "a", "password": "p"}},
        "steps": [{
            "name": "read", "type": "attack", "as": "u",
            "request": {"method": "GET", "path": "/secret"},
            "expect": {"status": [401, 403]},
        }],
    }
    result, _ = run(scenario, router)
    assert result.verdict is Verdict.SECURE


def test_setup_failure_is_error_and_skips_rest():
    router = Router().add("GET", "/prep", make_response(500))
    scenario = {
        "id": "s", "name": "n", "severity": "high", "wstg": "WSTG-ATHZ-04",
        "steps": [
            {"name": "prep", "type": "setup", "request": {"method": "GET", "path": "/prep"},
             "expect": {"status": 200}},
            {"name": "attack", "type": "attack", "request": {"method": "GET", "path": "/x"},
             "expect": {"status": [401]}},
        ],
    }
    result, fake = run(scenario, router)
    assert result.verdict is Verdict.ERROR
    assert result.steps[0].outcome is StepOutcome.ERROR
    assert result.steps[1].outcome is StepOutcome.SKIPPED
    assert fake.sent_to("GET", "/x") == []        # второй шаг не отправлялся


def test_secure_if_stops_scenario_as_secure():
    router = Router().add("POST", "/register", make_response(400, json={"detail": "rejected"}))
    scenario = {
        "id": "s", "name": "n", "severity": "high", "wstg": "WSTG-INPV-01",
        "steps": [
            {"name": "reg", "type": "setup", "request": {"method": "POST", "path": "/register"},
             "secure_if": {"status": [400, 422]}, "expect": {"status": 200}},
            {"name": "after", "type": "attack", "request": {"method": "GET", "path": "/me"},
             "expect": {"status": [401]}},
        ],
    }
    result, fake = run(scenario, router)
    assert result.verdict is Verdict.SECURE
    assert result.steps[0].secure_if_hit is True
    assert result.steps[1].outcome is StepOutcome.SKIPPED
    assert fake.sent_to("GET", "/me") == []


# ── save → использование в следующем шаге ───────────────────────────────────
def test_save_find_all_then_use_in_next_request():
    router = Router()
    router.add("GET", "/_debug", make_response(200, json={"users": [
        {"username": "x", "admin": False, "password": "px"},
        {"username": "root", "admin": True, "password": "pr"},
    ]}))
    router.add("POST", "/users/v1/login", make_response(200, json={"auth_token": "T"}))
    scenario = {
        "id": "s", "name": "n", "severity": "critical", "wstg": "WSTG-ATHN-04",
        "steps": [
            {"name": "leak", "type": "setup", "request": {"method": "GET", "path": "/_debug"},
             "save": {"admins": {"from": "users", "where": {"admin": True}, "all": True}},
             "expect": {"status": 200}},
            {"name": "login", "type": "attack",
             "request": {"method": "POST", "path": "/users/v1/login",
                         "json": {"username": "${admins.0.username}", "password": "${admins.0.password}"}},
             "expect": {"status": [401, 403]}},
        ],
    }
    result, fake = run(scenario, router)
    assert result.verdict is Verdict.VULNERABLE          # логин вернул 200, а ждали отказ
    login_req = fake.sent_to("POST", "/users/v1/login")[-1]
    assert login_req.body.content == {"username": "root", "password": "pr"}


def test_extraction_failure_is_error():
    router = Router().add("GET", "/x", make_response(200, json={"nope": 1}))
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "steps": [{"name": "s", "type": "setup", "request": {"method": "GET", "path": "/x"},
                   "save": {"tok": "auth_token"}, "expect": {"status": 200}}],
    }
    result, _ = run(scenario, router)
    assert result.verdict is Verdict.ERROR
    assert "save" in result.steps[0].error


# ── авторизация ─────────────────────────────────────────────────────────────
def test_lazy_login_is_cached_across_steps():
    router = Router()
    login_route(router)
    router.add("GET", "/a", make_response(403))
    router.add("GET", "/b", make_response(403))
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "roles": {"u": {"username": "a", "password": "p"}},
        "steps": [
            {"name": "a", "type": "attack", "as": "u", "request": {"method": "GET", "path": "/a"},
             "expect": {"status": [401, 403]}},
            {"name": "b", "type": "attack", "as": "u", "request": {"method": "GET", "path": "/b"},
             "expect": {"status": [401, 403]}},
        ],
    }
    result, fake = run(scenario, router)
    assert result.verdict is Verdict.SECURE
    assert len(fake.sent_to("POST", "/users/v1/login")) == 1     # залогинились один раз


def test_undeclared_role_is_error():
    router = Router().add("GET", "/x", make_response(200))
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "steps": [{"name": "s", "type": "attack", "as": "ghost",
                   "request": {"method": "GET", "path": "/x"}, "expect": {"status": [401]}}],
    }
    result, _ = run(scenario, router)
    assert result.verdict is Verdict.ERROR


def test_failed_login_makes_step_error():
    router = Router().add("POST", "/users/v1/login", make_response(401, json={"detail": "bad creds"}))
    router.add("GET", "/x", make_response(200))
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "roles": {"u": {"username": "a", "password": "wrong"}},
        "steps": [{"name": "s", "type": "attack", "as": "u",
                   "request": {"method": "GET", "path": "/x"}, "expect": {"status": [401]}}],
    }
    result, fake = run(scenario, router)
    assert result.verdict is Verdict.ERROR
    assert fake.sent_to("GET", "/x") == []        # до запроса шага не дошли


# ── vars из run_id / env ────────────────────────────────────────────────────
def test_vars_rendered_from_run_id_and_env():
    router = Router().add("POST", "/echo", make_response(200, json={"ok": True}))
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "vars": {"book": "book-${run_id}", "who": "${env.USER}"},
        "steps": [{"name": "s", "type": "setup",
                   "request": {"method": "POST", "path": "/echo",
                               "json": {"title": "${book}", "who": "${who}"}},
                   "expect": {"status": 200}}],
    }
    result, fake = run(scenario, router, env={"USER": "alice"})
    assert result.verdict is Verdict.SECURE
    body = fake.sent_to("POST", "/echo")[0].body.content
    assert body == {"title": "book-RID", "who": "alice"}
