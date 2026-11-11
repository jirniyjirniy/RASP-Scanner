"""Тело запроса любого типа: валидация формата, сборка в движке, маппинг в httpx."""

import pytest
from pydantic import ValidationError

from rasp_scanner.adapters.httpx_client import _body_kwargs
from rasp_scanner.config import RunnerConfig
from rasp_scanner.domain.enums import BodyKind
from rasp_scanner.domain.http import FilePart, RequestBody
from rasp_scanner.domain.scenario import Request, Scenario
from rasp_scanner.service_layer.engine import ScenarioRunner

from _doubles import FakeHttpClient, FixedClock, Router, make_response

CONFIG = RunnerConfig(target="http://test")


# ── валидация формата запроса ────────────────────────────────────────────────
def test_two_bodies_rejected():
    with pytest.raises(ValidationError):
        Request.model_validate({"method": "POST", "path": "/x", "json": {"a": 1}, "form": {"b": 2}})


def test_files_require_multipart():
    with pytest.raises(ValidationError):
        Request.model_validate({"method": "POST", "path": "/x", "files": {"f": {"filename": "a"}}})


def test_content_type_requires_raw():
    with pytest.raises(ValidationError):
        Request.model_validate({"method": "POST", "path": "/x", "json": {"a": 1}, "content_type": "x"})


def test_body_fields_picks_the_chosen_kind():
    r = Request.model_validate({"method": "POST", "path": "/x", "form": {"a": "${v}"}})
    kind, content, files, ct = r.body_fields()
    assert kind is BodyKind.FORM and content == {"a": "${v}"} and files is None


# ── сборка тела в движке (рендер ${...} + корректный RequestBody) ────────────
def _send(request_dict):
    scenario = {
        "id": "s", "name": "n", "severity": "low", "wstg": "WSTG-ATHZ-04",
        "vars": {"v": "hello-${run_id}"},
        "steps": [{"name": "s", "type": "setup", "request": request_dict, "expect": {"status": 200}}],
    }
    router = Router().add(request_dict["method"], request_dict["path"], make_response(200, json={"ok": True}))
    runner = ScenarioRunner(FakeHttpClient(router), CONFIG, run_id="RID", clock=FixedClock(), env={})
    fake = runner._http  # type: ignore[attr-defined]
    runner.run(Scenario.model_validate(scenario))
    return fake.requests[0].body


def test_engine_builds_form_body():
    body = _send({"method": "POST", "path": "/x", "form": {"q": "${v}"}})
    assert body.kind is BodyKind.FORM and body.content == {"q": "hello-RID"}


def test_engine_builds_raw_body_with_content_type():
    body = _send({"method": "POST", "path": "/x", "raw": "<x>${v}</x>", "content_type": "application/xml"})
    assert body.kind is BodyKind.RAW
    assert body.content == "<x>hello-RID</x>" and body.content_type == "application/xml"


def test_engine_builds_multipart_with_file():
    body = _send({
        "method": "POST", "path": "/x",
        "multipart": {"field": "${v}"},
        "files": {"doc": {"filename": "a-${run_id}.txt", "content": "data-${v}", "content_type": "text/plain"}},
    })
    assert body.kind is BodyKind.MULTIPART
    assert body.content == {"field": "hello-RID"}
    assert body.files["doc"].filename == "a-RID.txt"
    assert body.files["doc"].content == "data-hello-RID"


# ── маппинг RequestBody → kwargs httpx ───────────────────────────────────────
def test_kwargs_json():
    assert _body_kwargs(RequestBody(BodyKind.JSON, {"a": 1}), {}) == {"json": {"a": 1}}


def test_kwargs_form():
    assert _body_kwargs(RequestBody(BodyKind.FORM, {"a": 1}), {}) == {"data": {"a": 1}}


def test_kwargs_multipart():
    body = RequestBody(BodyKind.MULTIPART, {"f": "v"}, files={"d": FilePart("a.txt", "x", "text/plain")})
    kwargs = _body_kwargs(body, {})
    assert kwargs["data"] == {"f": "v"}
    assert kwargs["files"] == {"d": ("a.txt", "x", "text/plain")}


def test_kwargs_raw_sets_content_type_without_clobbering_explicit():
    headers = {}
    assert _body_kwargs(RequestBody(BodyKind.RAW, "<x/>", content_type="application/xml"), headers) == {"content": "<x/>"}
    assert headers["Content-Type"] == "application/xml"
    # явный заголовок шага не перетирается
    explicit = {"Content-Type": "text/plain"}
    _body_kwargs(RequestBody(BodyKind.RAW, "<x/>", content_type="application/xml"), explicit)
    assert explicit["Content-Type"] == "text/plain"
