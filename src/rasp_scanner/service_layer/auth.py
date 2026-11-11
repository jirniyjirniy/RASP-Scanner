"""Менеджер авторизации (per-scenario).

Собирает «учётную декорацию» запроса под выбранную в конфиге механику входа и
накладывает её на запросы шага (`decorate`). Поддержано:

  • type=login  — ленивый логин телом любого типа (json/form/raw/multipart),
                  токен из JSON-тела / заголовка / cookie / regex ответа,
                  опц. session-cookies на последующие запросы;
  • type=basic  — HTTP Basic из учётки роли;
  • type=static — без логина: готовые значения (API-key/токен) из env;
  • type=none   — без авторизации.

Плюс опциональный CSRF pre-flow: один раз выбираем страницу, достаём токен и
подставляем его (и cookies выборки) во все последующие запросы и в сам логин.

Механика берётся из конфига раннера, а не из сценария — поэтому один сценарий
переносим между стендами.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field, replace

from ..config import InjectRule, RunnerConfig, TokenSpec
from ..domain import jsonquery
from ..domain.bodies import materialize
from ..domain.context import Context
from ..domain.errors import AuthError
from ..domain.http import HttpRequest, HttpResponse
from ..domain.rendering import Renderer
from ..domain.scenario import Role
from ..ports.http import HttpClient


@dataclass(slots=True)
class Credential:
    """Что добавить к запросу для авторизации: заголовки, cookies, query-параметры."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)

    def merge(self, other: "Credential") -> None:
        self.headers.update(other.headers)
        self.cookies.update(other.cookies)
        self.query.update(other.query)


class AuthManager:
    def __init__(
        self,
        http: HttpClient,
        config: RunnerConfig,
        roles: dict[str, Role],
        context: Context,
    ) -> None:
        self._http = http
        self._config = config
        self._roles = roles
        self._context = context
        self._cache: dict[str, Credential] = {}   # учётка по имени роли
        self._csrf: Credential | None = None       # CSRF-декорация (одна на сценарий)

    # ── применение к запросу шага ────────────────────────────────────────────
    def decorate(self, request: HttpRequest, role_name: str) -> HttpRequest:
        """Наложить учётную декорацию роли на запрос (явные значения шага в приоритете)."""
        return _apply(request, self._credential_for(role_name))

    def _credential_for(self, role_name: str) -> Credential:
        if role_name in self._cache:
            return self._cache[role_name]

        cred = Credential()
        cred.merge(self._csrf_credential())   # CSRF (если включён) — на любой тип

        auth_type = self._config.auth.type
        if auth_type == "login":
            cred.merge(self._login_credential(role_name))
        elif auth_type == "basic":
            cred.merge(self._basic_credential(role_name))
        elif auth_type == "static":
            cred.merge(self._static_credential())
        # type == "none" → только CSRF (если был)

        self._cache[role_name] = cred
        return cred

    # ── type=login ───────────────────────────────────────────────────────────
    def _login_credential(self, role_name: str) -> Credential:
        login = self._config.auth.login
        role = self._role(role_name)

        main = Renderer(self._context)
        username = main.render(role.username) if role.username is not None else None
        email = main.render(role.email) if role.email is not None else None
        password = main.render(role.password)
        identity = username if username is not None else email

        body_ctx = self._context.derive(
            {"username": username, "email": email, "identity": identity, "password": password}
        )
        body = materialize(login.body.body_fields(), Renderer(body_ctx))
        request = _apply(
            HttpRequest(method=login.method.value, url=f"{self._config.base_url}{login.path}", body=body),
            self._csrf_credential(),   # логин тоже может требовать CSRF-токен
        )

        response = self._send(request, what=f"логин роли {role_name!r}")
        if response.status_code >= 400:
            raise AuthError(
                f"логин роли {role_name!r} отклонён: HTTP {response.status_code} — {response.text[:200]}"
            )

        token = self._extract(response, login.token, what=f"логин роли {role_name!r}")
        cred = Credential()
        self._apply_inject(self._config.auth.inject, token, cred)
        if login.session:
            cred.cookies.update(response.cookies)   # нести сессию дальше
        return cred

    # ── type=basic ───────────────────────────────────────────────────────────
    def _basic_credential(self, role_name: str) -> Credential:
        role = self._role(role_name)
        main = Renderer(self._context)
        identity = main.render(role.username) if role.username is not None else main.render(role.email)
        password = main.render(role.password)
        token = base64.b64encode(f"{identity}:{password}".encode()).decode()
        header = self._config.auth.basic.header if self._config.auth.basic else "Authorization"
        return Credential(headers={header: f"Basic {token}"})

    # ── type=static ──────────────────────────────────────────────────────────
    def _static_credential(self) -> Credential:
        cred = Credential()
        rules = self._config.auth.static.inject if self._config.auth.static else []
        self._apply_inject(rules, token="", cred=cred)
        return cred

    # ── CSRF pre-flow (ленивый, один на сценарий) ────────────────────────────
    def _csrf_credential(self) -> Credential:
        csrf = self._config.auth.csrf
        if not csrf or not csrf.enabled:
            return Credential()
        if self._csrf is not None:
            return self._csrf

        r = Renderer(self._context)
        request = HttpRequest(
            method=csrf.fetch.method.value,
            url=f"{self._config.base_url}{r.render(csrf.fetch.path)}",
            headers={k: str(v) for k, v in r.render(csrf.fetch.headers).items()},
            params=r.render(csrf.fetch.params),
        )
        response = self._send(request, what="CSRF pre-flow")
        token = self._extract(response, csrf.token, what="CSRF pre-flow")
        cred = Credential()
        self._apply_inject([csrf.inject], token, cred)
        cred.cookies.update(response.cookies)   # cookies выборки нужны вместе с токеном
        self._csrf = cred
        return cred

    # ── вспомогательное ──────────────────────────────────────────────────────
    def _apply_inject(self, rules: list[InjectRule], token: str, cred: Credential) -> None:
        renderer = Renderer(self._context.derive({"token": token}))
        for rule in rules:
            value = str(renderer.render(rule.template))
            if rule.into == "header":
                cred.headers[rule.name] = value
            elif rule.into == "cookie":
                cred.cookies[rule.name] = value
            else:  # query
                cred.query[rule.name] = value

    def _extract(self, response: HttpResponse, spec: TokenSpec, *, what: str) -> str:
        if spec.source == "json":
            body = response.json_or_none()
            token = jsonquery.query_first(body, spec.path, default=None) if body is not None else None
        elif spec.source == "header":
            token = _header_get(response.headers, spec.header)
        elif spec.source == "cookie":
            token = response.cookies.get(spec.cookie)
        else:  # regex
            match = re.search(spec.regex, response.text)
            token = match.group(1) if match else None
        if not token:
            raise AuthError(f"{what}: не удалось извлечь токен (source={spec.source})")
        return str(token)

    def _send(self, request: HttpRequest, *, what: str) -> HttpResponse:
        try:
            return self._http.send(request)
        except Exception as exc:
            raise AuthError(f"{what} не отправился: {exc}") from exc

    def _role(self, role_name: str) -> Role:
        role = self._roles.get(role_name)
        if role is None:
            raise AuthError(f"роль {role_name!r} не объявлена в roles сценария")
        return role


def _apply(request: HttpRequest, cred: Credential) -> HttpRequest:
    """Наложить декорацию на запрос. Явные значения запроса перекрывают учётку."""
    return replace(
        request,
        headers={**cred.headers, **request.headers},
        params={**cred.query, **request.params},
        cookies={**cred.cookies, **request.cookies},
    )


def _header_get(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None
