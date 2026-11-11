"""Редакция секретов: юнит-тесты Redactor + end-to-end «пароль не утёк в отчёт»."""

import json

from rasp_scanner.adapters import serialization
from rasp_scanner.adapters.reporters import ConsoleReporter, HtmlReporter, JsonReporter
from rasp_scanner.config import RunnerConfig
from rasp_scanner.domain.redaction import REDACTED, Redactor, is_sensitive_key
from rasp_scanner.domain.http import RequestBody
from rasp_scanner.domain.results import (
    CheckResult,
    RequestSnapshot,
    ResponseSnapshot,
    StepResult,
)
from rasp_scanner.domain.enums import BodyKind, StepOutcome, StepType
from rasp_scanner.domain.scenario import Scenario
from rasp_scanner.service_layer.engine import ScenarioRunner

from _doubles import FakeHttpClient, FixedClock, Router, make_response


# ── Redactor: по имени ключа ────────────────────────────────────────────────
def test_structured_redacts_by_sensitive_key():
    out = Redactor().redact_structured({"username": "bob", "password": "pass1"})
    assert out == {"username": "bob", "password": REDACTED}


def test_structured_redacts_nested_and_in_lists():
    data = {"users": [{"name": "a", "password": "x"}, {"name": "b", "pwd": "y"}]}
    out = Redactor().redact_structured(data)
    assert out["users"][0]["password"] == REDACTED
    assert out["users"][1]["pwd"] == REDACTED
    assert out["users"][0]["name"] == "a"


def test_sensitive_key_matching():
    assert is_sensitive_key("password") and is_sensitive_key("new_password")
    assert is_sensitive_key("auth_token") and is_sensitive_key("API_KEY")
    assert not is_sensitive_key("username") and not is_sensitive_key("email")


# ── Redactor: тело ответа (строка, в т.ч. обрезанная) ───────────────────────
def test_body_regex_redacts_password_field():
    body = '{\n  "username": "name1",\n  "password": "pass1"\n}'
    out = Redactor().redact_body(body)
    assert "pass1" not in out
    assert "name1" in out
    assert REDACTED in out


def test_body_regex_handles_truncated_json():
    # обрезанное тело — невалидный JSON, но поле пароля всё равно должно вычиститься
    body = '{"users": [{"password": "leaked", "admin": true'
    out = Redactor().redact_body(body)
    assert "leaked" not in out


# ── Redactor: по значению (свободный текст) ─────────────────────────────────
def test_text_redacts_known_secret_value():
    r = Redactor({"Pwned-abc123"})
    msg = "тело НЕ содержит 'Pwned-abc123'"
    assert "Pwned-abc123" not in r.redact_text(msg)
    assert REDACTED in r.redact_text(msg)


def test_text_leaves_non_secret_intact():
    assert Redactor({"Pwned-abc"}).redact_text("status 200 ∈ [401, 403]") == "status 200 ∈ [401, 403]"


# ── Redactor: scrub_step целиком ────────────────────────────────────────────
def test_scrub_step_cleans_request_response_checks_saved():
    step = StepResult(
        name="s", type=StepType.ATTACK, outcome=StepOutcome.VULNERABLE,
        request=RequestSnapshot(
            "POST", "http://t/login",
            body=RequestBody(BodyKind.JSON, {"username": "u", "password": "SeCret1"}),
            cookies={"session": "abc123"},
        ),
        response=ResponseSnapshot(200, body='{"password": "pass1"}'),
        checks=[CheckResult("body_not_contains", False, "тело НЕ содержит 'SeCret1'")],
        saved={"admins": [{"username": "admin", "password": "pass1"}]},
    )
    Redactor({"SeCret1"}).scrub_step(step)

    assert step.request.body.content["password"] == REDACTED
    assert step.request.cookies["session"] == REDACTED
    assert "pass1" not in step.response.body
    assert "SeCret1" not in step.checks[0].message
    assert step.saved["admins"][0]["password"] == REDACTED


# ── End-to-end: ни один репортёр не выносит пароль ──────────────────────────
def _debug_leak_scenario() -> dict:
    return {
        "id": "leak", "name": "debug leak", "severity": "critical", "wstg": "WSTG-ATHN-04",
        "steps": [
            {
                "name": "debug dump", "type": "setup",
                "request": {"method": "GET", "path": "/users/v1/_debug"},
                "save": {"admins": {"from": "users", "where": {"admin": True}, "all": True}},
                "expect": {"status": 200},
            },
            {
                "name": "login as leaked admin", "type": "attack",
                "request": {
                    "method": "POST", "path": "/users/v1/login",
                    "json": {"username": "${admins.0.username}", "password": "${admins.0.password}"},
                },
                "expect": {"status": [401, 403], "body_not_contains": "auth_token"},
            },
        ],
    }


def _run_leak():
    dump = {"users": [
        {"username": "admin", "password": "pass1", "admin": True},
        {"username": "name1", "password": "pass2", "admin": False},
    ]}
    router = Router()
    router.add("GET", "/users/v1/_debug", make_response(200, json=dump))
    router.add("POST", "/users/v1/login", make_response(200, json={"auth_token": "TOK"}))
    runner = ScenarioRunner(
        FakeHttpClient(router), RunnerConfig(target="http://test"),
        run_id="RID", clock=FixedClock(), env={},
    )
    return runner.run(Scenario.model_validate(_debug_leak_scenario()))


def test_leaked_seed_passwords_absent_from_all_reporters():
    result = _run_leak()
    for text in (
        JsonReporter().render(_as_run(result)),
        HtmlReporter().render(_as_run(result)),
        ConsoleReporter(color=False).render(_as_run(result)),
    ):
        assert "pass1" not in text
        assert "pass2" not in text


def test_leaked_passwords_absent_from_serialized_structures():
    result = _run_leak()
    blob = json.dumps(serialization.scenario_to_dict(result), ensure_ascii=False)
    assert "pass1" not in blob and "pass2" not in blob
    # редакция затронула именно пароли, а не имена пользователей
    assert "admin" in blob


# маленький помощник: завернуть один ScenarioResult в RunResult для репортёров
def _as_run(scenario_result):
    from datetime import datetime, timezone

    from rasp_scanner.domain.results import RunResult

    return RunResult(
        run_id="RID", target="http://test", scenarios=[scenario_result],
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
