"""Проверки (Assertions): evaluate(Expect) → список CheckResult.

Один и тот же код обслуживает expect и secure_if — различие только в том, как
движок трактует результат. Операнды проверок прогоняются через Renderer, поэтому
в ожиданиях можно писать ${...} (напр. `$.data.username: ${who}`).

Expect считается ВЫПОЛНЕННЫМ, если прошли ВСЕ входящие в него проверки.
"""

from __future__ import annotations

from typing import Any

from . import jsonquery
from .context import Context
from .http import HttpResponse
from .rendering import Renderer
from .results import CheckResult
from .scenario import Expect, VarCheck

_MISSING = object()


def evaluate(expect: Expect, response: HttpResponse, context: Context) -> list[CheckResult]:
    renderer = Renderer(context)
    checks: list[CheckResult] = []

    if expect.status is not None:
        checks.append(_check_status(expect.status, response))

    if expect.json_body:
        body = response.json_or_none()
        for path, expected_tpl in expect.json_body.items():
            checks.append(_check_json(body, path, renderer.render(expected_tpl)))

    if expect.body_contains is not None:
        needle = renderer.render(expect.body_contains)
        checks.append(
            CheckResult(
                "body_contains",
                str(needle) in response.text,
                f"тело содержит {needle!r}",
            )
        )

    if expect.body_not_contains is not None:
        needle = renderer.render(expect.body_not_contains)
        checks.append(
            CheckResult(
                "body_not_contains",
                str(needle) not in response.text,
                f"тело НЕ содержит {needle!r}",
            )
        )

    for var_name, var_check in expect.vars.items():
        checks.extend(_check_var(var_name, var_check, context, renderer))

    return checks


def passed(checks: list[CheckResult]) -> bool:
    return all(c.passed for c in checks)


# ── отдельные проверки ───────────────────────────────────────────────────────
def _check_status(allowed: list[int], response: HttpResponse) -> CheckResult:
    ok = response.status_code in allowed
    return CheckResult("status", ok, f"status {response.status_code} ∈ {allowed}")


def _check_json(body: Any, path: str, expected: Any) -> CheckResult:
    if body is None:
        return CheckResult("json", False, f"{path}: тело не JSON")
    matches = jsonquery.query_all(body, path)
    if not matches:
        return CheckResult("json", False, f"{path}: путь не найден (ожидалось {expected!r})")
    actual = matches[0]
    return CheckResult("json", actual == expected, f"{path} = {actual!r} (ожидалось {expected!r})")


def _check_var(
    name: str, check: VarCheck, context: Context, renderer: Renderer
) -> list[CheckResult]:
    try:
        value = context.resolve(name)
    except Exception as exc:  # неизвестная переменная в проверке → это провал проверки
        return [CheckResult("vars", False, f"{name}: {exc}")]

    out: list[CheckResult] = []
    if check.eq is not None:
        expected = renderer.render(check.eq)
        out.append(CheckResult("vars.eq", value == expected, f"{name} == {expected!r} (факт {value!r})"))
    if check.contains is not None:
        needle = renderer.render(check.contains)
        out.append(CheckResult("vars.contains", _contains(value, needle), f"{name} содержит {needle!r}"))
    if check.not_contains is not None:
        needle = renderer.render(check.not_contains)
        out.append(
            CheckResult("vars.not_contains", not _contains(value, needle), f"{name} НЕ содержит {needle!r}")
        )
    if check.length is not None:
        actual_len = len(value) if hasattr(value, "__len__") else None
        out.append(
            CheckResult("vars.length", actual_len == check.length, f"len({name}) = {actual_len} (ожидалось {check.length})")
        )
    return out


def _contains(haystack: Any, needle: Any) -> bool:
    if isinstance(haystack, str):
        return str(needle) in haystack
    if isinstance(haystack, (list, tuple, set, dict)):
        return needle in haystack
    return False
