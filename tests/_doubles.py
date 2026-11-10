"""Тестовые дублёры (fake-адаптеры портов) — импортируются тестами напрямую.

Лежит в каталоге tests, добавленном в pythonpath (см. pyproject). Отдельный
модуль, а не conftest, чтобы классы можно было честно импортировать.
"""

from __future__ import annotations

import json as _json
from collections.abc import Callable
from datetime import datetime, timezone

from rasp_scanner.domain.http import HttpRequest, HttpResponse
from rasp_scanner.ports.clock import Clock, RunIdProvider
from rasp_scanner.ports.http import HttpClient


def make_response(status: int = 200, *, json=None, text: str | None = None) -> HttpResponse:
    if text is None:
        text = _json.dumps(json) if json is not None else ""
    return HttpResponse(status_code=status, headers={"content-type": "application/json"}, text=text)


class FakeHttpClient(HttpClient):
    """Отдаёт ответы по правилу handler(request)->HttpResponse и пишет историю."""

    def __init__(self, handler: Callable[[HttpRequest], HttpResponse]) -> None:
        self._handler = handler
        self.requests: list[HttpRequest] = []
        self.closed = False

    def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        return self._handler(request)

    def close(self) -> None:
        self.closed = True

    def sent_to(self, method: str, path_suffix: str) -> list[HttpRequest]:
        return [r for r in self.requests if r.method == method and r.url.split("?")[0].endswith(path_suffix)]


class Router:
    """Простой роутер ответов по (METHOD, окончание пути). Иначе — 404."""

    def __init__(self) -> None:
        self._routes: list[tuple[str, str, Callable[[HttpRequest], HttpResponse]]] = []

    def add(self, method: str, path_suffix: str, responder) -> "Router":
        fn = responder if callable(responder) else (lambda _req, r=responder: r)
        self._routes.append((method, path_suffix, fn))
        return self

    def __call__(self, request: HttpRequest) -> HttpResponse:
        for method, suffix, fn in self._routes:
            if request.method == method and request.url.split("?")[0].endswith(suffix):
                return fn(request)
        return make_response(404, json={"detail": "no route"})


class FixedRunId(RunIdProvider):
    def __init__(self, *ids: str) -> None:
        self._ids = list(ids) or ["run0"]
        self._i = 0

    def new_run_id(self) -> str:
        rid = self._ids[min(self._i, len(self._ids) - 1)]
        self._i += 1
        return rid


class FixedClock(Clock):
    def __init__(self, moment: datetime | None = None) -> None:
        self._moment = moment or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._moment
