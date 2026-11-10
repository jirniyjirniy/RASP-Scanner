"""Движок: исполнение шага и сценария.

Порядок внутри шага фиксирован контрактом формата: render → send → save →
secure_if → expect. Трактовка результата зависит от типа шага:
    setup : expect не прошёл → ERROR (подготовка не удалась, стоп)
    attack: expect не прошёл → VULNERABLE, прошёл → SECURE

Остановка сценария: ERROR (сразу) или сработавший secure_if (вердикт SECURE).
Иначе идём до конца — attack-шаги собирают доказательства.
"""

from __future__ import annotations

import time
from typing import Any

from ..config import RunnerConfig
from ..domain import assertions
from ..domain.context import Context
from ..domain.enums import StepOutcome, StepType
from ..domain.errors import ExtractionError, RenderError, ScannerError
from ..domain.extraction import extract
from ..domain.http import HttpRequest, HttpResponse
from ..domain.rendering import Renderer
from ..domain.results import (
    RequestSnapshot,
    ResponseSnapshot,
    ScenarioResult,
    StepResult,
)
from ..domain.scenario import Scenario, Step
from ..domain.verdict import fold_steps
from ..ports.clock import Clock
from ..ports.http import HttpClient
from .auth import AuthManager

_REDACTED = "***redacted***"
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}


class StepExecutor:
    """Исполняет один шаг в контексте сценария."""

    def __init__(
        self,
        http: HttpClient,
        config: RunnerConfig,
        auth: AuthManager,
        context: Context,
    ) -> None:
        self._http = http
        self._config = config
        self._auth = auth
        self._context = context

    def execute(self, step: Step) -> StepResult:
        start = time.perf_counter()
        renderer = Renderer(self._context)

        # 1. render: материализуем запрос из спека
        try:
            request = self._build_request(step, renderer)
        except RenderError as exc:
            return self._error(step, start, f"подстановка ${{...}} не удалась: {exc}")

        # 2. auth: ленивый логин + инъекция токена, если указан as
        if step.as_role is not None:
            try:
                auth_headers = self._auth.headers_for(step.as_role)
                # явные заголовки шага перекрывают инъекцию (можно задать токен вручную)
                request = self._with_headers(request, {**auth_headers, **request.headers})
            except ScannerError as exc:
                return self._error(step, start, str(exc), request=request)

        req_snapshot = self._snapshot_request(request)

        # 3. send
        try:
            response = self._http.send(request)
        except Exception as exc:
            return self._error(step, start, f"запрос не выполнен: {exc}", request=request)

        resp_snapshot = self._snapshot_response(response)

        # 4. save: извлекаем значения ДО проверок
        saved: dict[str, Any] = {}
        try:
            self._apply_saves(step, response, renderer, saved)
        except ExtractionError as exc:
            return self._error(
                step, start, f"save не удался: {exc}", request=request,
                response=response, saved=saved,
            )

        # 5. secure_if: сервер сам отбил атаку?
        if step.secure_if is not None:
            checks = assertions.evaluate(step.secure_if, response, self._context)
            if assertions.passed(checks):
                return self._result(
                    step, start, StepOutcome.SECURE, checks=checks, saved=saved,
                    request=request, response=response, secure_if_hit=True,
                )

        # 6. expect
        checks = assertions.evaluate(step.expect, response, self._context) if step.expect else []
        outcome = self._classify(step.type, assertions.passed(checks) if step.expect else True)
        return self._result(
            step, start, outcome, checks=checks, saved=saved,
            request=request, response=response,
        )

    # ── сборка запроса ───────────────────────────────────────────────────────
    def _build_request(self, step: Step, renderer: Renderer) -> HttpRequest:
        spec = step.request
        path = str(renderer.render(spec.path))
        headers = {k: str(v) for k, v in renderer.render(spec.headers).items()}
        params = renderer.render(spec.params)
        json_body = renderer.render(spec.json_body) if spec.json_body is not None else None
        return HttpRequest(
            method=spec.method.value,
            url=f"{self._config.base_url}{path}",
            headers=headers,
            params=params,
            json_body=json_body,
        )

    @staticmethod
    def _with_headers(request: HttpRequest, headers: dict[str, str]) -> HttpRequest:
        return HttpRequest(
            method=request.method, url=request.url, headers=headers,
            params=request.params, json_body=request.json_body,
        )

    def _apply_saves(
        self, step: Step, response: HttpResponse, renderer: Renderer, saved: dict[str, Any]
    ) -> None:
        if not step.save:
            return
        data = response.json_or_none()
        for name, rule in step.save.items():
            value = extract(rule, data, renderer)
            self._context.set(name, value)
            saved[name] = value

    # ── классификация исхода ────────────────────────────────────────────────
    @staticmethod
    def _classify(step_type: StepType, expect_ok: bool) -> StepOutcome:
        if step_type is StepType.SETUP:
            return StepOutcome.PASSED if expect_ok else StepOutcome.ERROR
        # attack
        return StepOutcome.SECURE if expect_ok else StepOutcome.VULNERABLE

    # ── снимки для отчёта ────────────────────────────────────────────────────
    def _snapshot_request(self, request: HttpRequest) -> RequestSnapshot:
        return RequestSnapshot(
            method=request.method, url=request.url,
            headers=_redact_headers(request.headers),
            params=request.params, json_body=request.json_body,
        )

    def _snapshot_response(self, response: HttpResponse) -> ResponseSnapshot:
        limit = self._config.max_body_chars
        body = response.text
        if len(body) > limit:
            body = body[:limit] + f"\n… (обрезано, всего {len(response.text)} символов)"
        return ResponseSnapshot(
            status_code=response.status_code, headers=dict(response.headers),
            body=body, elapsed_ms=response.elapsed_ms,
        )

    # ── фабрики StepResult ───────────────────────────────────────────────────
    def _result(
        self, step: Step, start: float, outcome: StepOutcome, *,
        checks=None, saved=None, request: HttpRequest | None = None,
        response: HttpResponse | None = None, secure_if_hit: bool = False,
    ) -> StepResult:
        return StepResult(
            name=step.name, type=step.type, outcome=outcome, as_role=step.as_role,
            request=self._snapshot_request(request) if request else None,
            response=self._snapshot_response(response) if response else None,
            checks=checks or [], saved=saved or {}, secure_if_hit=secure_if_hit,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    def _error(
        self, step: Step, start: float, message: str, *,
        request: HttpRequest | None = None, response: HttpResponse | None = None,
        saved=None,
    ) -> StepResult:
        result = self._result(
            step, start, StepOutcome.ERROR, request=request, response=response, saved=saved,
        )
        result.error = message
        return result


class ScenarioRunner:
    """Прогоняет один сценарий целиком и выносит вердикт."""

    def __init__(
        self, http: HttpClient, config: RunnerConfig, *,
        run_id: str, clock: Clock, env: dict[str, str],
    ) -> None:
        self._http = http
        self._config = config
        self._run_id = run_id
        self._clock = clock
        self._env = env

    def run(self, scenario: Scenario) -> ScenarioResult:
        started = self._clock.now()

        # контекст + рендер пользовательских vars (они могут ссылаться на run_id/env)
        context = Context(self._run_id, self._env, {})
        try:
            self._seed_vars(scenario, context)
        except RenderError as exc:
            return self._failed_scenario(scenario, started, f"ошибка в vars: {exc}")

        auth = AuthManager(self._http, self._config, scenario.roles, context)
        executor = StepExecutor(self._http, self._config, auth, context)

        step_results: list[StepResult] = []
        stopped = False
        for step in scenario.steps:
            if stopped:
                step_results.append(_skipped(step))
                continue
            result = executor.execute(step)
            step_results.append(result)
            if result.outcome is StepOutcome.ERROR or result.secure_if_hit:
                stopped = True

        verdict = fold_steps(r.outcome for r in step_results)
        return self._scenario_result(scenario, started, verdict, step_results)

    def _seed_vars(self, scenario: Scenario, context: Context) -> None:
        renderer = Renderer(context)
        for name, raw in scenario.vars.items():
            context.set(name, renderer.render(raw))

    def _scenario_result(self, scenario, started, verdict, steps) -> ScenarioResult:
        return ScenarioResult(
            id=scenario.id, name=scenario.name, severity=scenario.severity,
            wstg=scenario.wstg, verdict=verdict, description=scenario.description,
            remediation=scenario.remediation, tags=scenario.tags, steps=steps,
            started_at=started, finished_at=self._clock.now(),
        )

    def _failed_scenario(self, scenario, started, message) -> ScenarioResult:
        from ..domain.enums import Verdict
        result = self._scenario_result(
            scenario, started, Verdict.ERROR, [_skipped(s) for s in scenario.steps]
        )
        result.error = message
        return result


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: (_REDACTED if k.lower() in _SENSITIVE_HEADERS else v) for k, v in headers.items()}


def _skipped(step: Step) -> StepResult:
    return StepResult(name=step.name, type=step.type, outcome=StepOutcome.SKIPPED, as_role=step.as_role)
