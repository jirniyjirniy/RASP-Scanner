"""Гибкая авторизация: источники токена, session-cookies, basic, static, CSRF."""

import base64
import json

from rasp_scanner.adapters import serialization
from rasp_scanner.domain.redaction import REDACTED
from rasp_scanner.config import (
    AuthConfig,
    BasicConfig,
    CsrfConfig,
    FetchSpec,
    InjectRule,
    LoginConfig,
    RunnerConfig,
    StaticConfig,
    TokenSpec,
)
from rasp_scanner.domain.enums import Verdict
from rasp_scanner.domain.scenario import Scenario
from rasp_scanner.service_layer.engine import ScenarioRunner

from _doubles import FakeHttpClient, FixedClock, Router, make_response

LOGIN = "/users/v1/login"


def _run(auth: AuthConfig, router: Router, *, with_role=True, env=None):
    roles = {"u": {"username": "bob", "password": "pw"}} if with_role else {}
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "roles": roles,
        "steps": [{
            "name": "go", "type": "setup", "as": "u",
            "request": {"method": "GET", "path": "/thing"},
            "expect": {"status": 200},
        }],
    }
    config = RunnerConfig(target="http://test", auth=auth)
    fake = FakeHttpClient(router)
    runner = ScenarioRunner(fake, config, run_id="RID", clock=FixedClock(), env=env or {})
    result = runner.run(Scenario.model_validate(scenario))
    return result, fake


def _thing(fake: FakeHttpClient):
    return fake.sent_to("GET", "/thing")[0]


# ── источники токена ─────────────────────────────────────────────────────────
def test_token_from_response_header():
    auth = AuthConfig(login=LoginConfig(token=TokenSpec(source="header", header="X-Auth")))
    router = (Router()
              .add("POST", LOGIN, make_response(200, headers={"x-auth": "HTOK"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    _, fake = _run(auth, router)
    assert _thing(fake).headers["Authorization"] == "Bearer HTOK"


def test_token_from_cookie():
    auth = AuthConfig(login=LoginConfig(token=TokenSpec(source="cookie", cookie="session")))
    router = (Router()
              .add("POST", LOGIN, make_response(200, cookies={"session": "CVAL"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    _, fake = _run(auth, router)
    assert _thing(fake).headers["Authorization"] == "Bearer CVAL"


def test_token_from_regex():
    auth = AuthConfig(login=LoginConfig(token=TokenSpec(source="regex", regex=r"token=([A-Z0-9]+)")))
    router = (Router()
              .add("POST", LOGIN, make_response(200, text="...token=ABC123; path=/"))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    _, fake = _run(auth, router)
    assert _thing(fake).headers["Authorization"] == "Bearer ABC123"


def test_missing_token_is_auth_error():
    auth = AuthConfig(login=LoginConfig(token=TokenSpec(source="json", path="nope")))
    router = (Router()
              .add("POST", LOGIN, make_response(200, json={"auth_token": "T"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    result, _ = _run(auth, router)
    assert result.verdict is Verdict.ERROR


# ── session-cookies ──────────────────────────────────────────────────────────
def test_session_cookies_carried_to_next_request():
    auth = AuthConfig(login=LoginConfig(session=True))
    router = (Router()
              .add("POST", LOGIN, make_response(200, json={"auth_token": "T"}, cookies={"sess": "S1"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    _, fake = _run(auth, router)
    req = _thing(fake)
    assert req.cookies["sess"] == "S1"
    assert req.headers["Authorization"] == "Bearer T"


def test_session_cookie_and_token_redacted_in_report():
    auth = AuthConfig(login=LoginConfig(session=True))
    router = (Router()
              .add("POST", LOGIN, make_response(200, json={"auth_token": "T"}, cookies={"sess": "S1"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    result, _ = _run(auth, router)
    blob = json.dumps(serialization.scenario_to_dict(result), ensure_ascii=False)
    assert "S1" not in blob and "Bearer T" not in blob
    assert REDACTED in blob   # cookie-значение/Authorization спрятаны, но ключи видны


# ── inject: куда класть ──────────────────────────────────────────────────────
def test_inject_into_cookie_and_query():
    auth = AuthConfig(inject=[
        InjectRule(into="cookie", name="token", template="${token}"),
        InjectRule(into="query", name="access_token", template="${token}"),
    ])
    router = (Router()
              .add("POST", LOGIN, make_response(200, json={"auth_token": "T"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    _, fake = _run(auth, router)
    req = _thing(fake)
    assert req.cookies["token"] == "T"
    assert req.params["access_token"] == "T"


# ── type=basic ───────────────────────────────────────────────────────────────
def test_basic_auth_from_role():
    auth = AuthConfig(type="basic", basic=BasicConfig())
    router = Router().add("GET", "/thing", make_response(200, json={"ok": True}))
    _, fake = _run(auth, router)
    expected = base64.b64encode(b"bob:pw").decode()
    assert _thing(fake).headers["Authorization"] == f"Basic {expected}"


# ── type=static ──────────────────────────────────────────────────────────────
def test_static_api_key_from_env():
    auth = AuthConfig(
        type="static",
        static=StaticConfig(inject=[InjectRule(into="header", name="X-API-Key", template="${env.KEY}")]),
    )
    router = Router().add("GET", "/thing", make_response(200, json={"ok": True}))
    _, fake = _run(auth, router, with_role=False, env={"KEY": "SECRET"})
    assert _thing(fake).headers["X-API-Key"] == "SECRET"


# ── CSRF pre-flow ────────────────────────────────────────────────────────────
def test_csrf_preflow_injects_token_and_cookies():
    auth = AuthConfig(
        type="none",
        csrf=CsrfConfig(
            enabled=True,
            fetch=FetchSpec(method="GET", path="/csrf"),
            token=TokenSpec(source="cookie", cookie="XSRF-TOKEN"),
            inject=InjectRule(into="header", name="X-XSRF-TOKEN", template="${token}"),
        ),
    )
    router = (Router()
              .add("GET", "/csrf", make_response(200, cookies={"XSRF-TOKEN": "CT"}))
              .add("GET", "/thing", make_response(200, json={"ok": True})))
    _, fake = _run(auth, router, with_role=False)
    req = _thing(fake)
    assert req.headers["X-XSRF-TOKEN"] == "CT"
    assert req.cookies["XSRF-TOKEN"] == "CT"
