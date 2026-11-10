"""Менеджер авторизации (per-scenario).

Реализует «ленивый логин»: роль логинится не заранее, а при первом обращении
(первое `as: <роль>` в шаге), после чего токен кешируется на весь сценарий.
Механика входа (endpoint, форма тела, путь к токену, как вставлять) берётся из
конфига раннера, а не из сценария — поэтому один сценарий переносим между стендами.
"""

from __future__ import annotations

from ..config import RunnerConfig
from ..domain import jsonquery
from ..domain.context import Context
from ..domain.errors import AuthError
from ..domain.http import HttpRequest
from ..domain.rendering import Renderer
from ..domain.scenario import Role
from ..ports.http import HttpClient


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
        self._tokens: dict[str, str] = {}   # кеш токенов по имени роли

    def token_for(self, role_name: str) -> str:
        if role_name in self._tokens:
            return self._tokens[role_name]

        role = self._roles.get(role_name)
        if role is None:
            raise AuthError(f"роль {role_name!r} не объявлена в roles сценария")

        token = self._login(role, role_name)
        self._tokens[role_name] = token
        return token

    def headers_for(self, role_name: str) -> dict[str, str]:
        """Заголовок(и) авторизации для вставки в запрос шага."""
        token = self.token_for(role_name)
        inject = self._config.auth.inject
        value = Renderer(self._context.derive({"token": token})).render(inject.template)
        return {inject.header: str(value)}

    def _login(self, role: Role, role_name: str) -> str:
        login = self._config.auth.login

        # имя/почта роли могут быть шаблонами (${env...}, ${attacker_name}) → рендерим
        main = Renderer(self._context)
        username = main.render(role.username) if role.username is not None else None
        email = main.render(role.email) if role.email is not None else None
        password = main.render(role.password)
        identity = username if username is not None else email

        body_ctx = self._context.derive(
            {"username": username, "email": email, "identity": identity, "password": password}
        )
        body = Renderer(body_ctx).render(login.body)

        request = HttpRequest(
            method=login.method.value,
            url=f"{self._config.base_url}{login.path}",
            json_body=body,
        )
        try:
            response = self._http.send(request)
        except Exception as exc:
            raise AuthError(f"логин роли {role_name!r} не отправился: {exc}") from exc

        if response.status_code >= 400:
            raise AuthError(
                f"логин роли {role_name!r} отклонён: HTTP {response.status_code} — {response.text[:200]}"
            )

        body_json = response.json_or_none()
        if body_json is None:
            raise AuthError(f"ответ логина роли {role_name!r} не JSON")

        token = jsonquery.query_first(body_json, login.token_path, default=None)
        if not token:
            raise AuthError(
                f"в ответе логина роли {role_name!r} нет токена по пути {login.token_path!r}"
            )
        return str(token)
