"""Конфигурация раннера (НЕ сценария).

Здесь живёт то, что общее для стенда, а не для конкретной уязвимости: базовый
адрес, как логиниться (endpoint, форма тела, где лежит токен) и как подставлять
токен в запросы. Именно поэтому один сценарий гоняется против любого стенда —
механика входа вынесена сюда.

Дефолты настроены под VAmPI, но переопределяются YAML-файлом (--config) и
переменными окружения (TARGET_URL) — удобно для CI.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .domain.enums import HttpMethod
from .domain.errors import ConfigError


class LoginConfig(BaseModel):
    """Как залогинить роль и где взять токен из ответа."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    method: HttpMethod = HttpMethod.POST
    path: str = "/users/v1/login"
    # шаблон тела логина. Доступные переменные: ${username} ${email} ${identity} ${password}
    body: dict[str, Any] = Field(
        default_factory=lambda: {"username": "${username}", "password": "${password}"}
    )
    # путь к токену в ответе логина (точечный или jsonpath)
    token_path: str = "auth_token"


class InjectConfig(BaseModel):
    """Как подставить токен авторизованной роли в запрос шага."""

    model_config = ConfigDict(extra="forbid")

    header: str = "Authorization"
    template: str = "Bearer ${token}"   # ${token} заменяется значением из token_path


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login: LoginConfig = Field(default_factory=LoginConfig)
    inject: InjectConfig = Field(default_factory=InjectConfig)


class RunnerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = "http://localhost:5001"
    auth: AuthConfig = Field(default_factory=AuthConfig)
    timeout: float = 15.0
    verify_tls: bool = True
    #: максимум символов тела ответа, попадающих в отчёт (защита от гигантских тел)
    max_body_chars: int = 8000

    @property
    def base_url(self) -> str:
        return self.target.rstrip("/")


def load_config(path: str | Path | None = None, *, target: str | None = None) -> RunnerConfig:
    """Собирает конфиг: файл (если задан) → переопределение TARGET_URL/--target."""
    data: dict[str, Any] = {}
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"файл конфигурации не найден: {p}")
        loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ConfigError(f"конфиг должен быть YAML-словарём, а не {type(loaded).__name__}")
        data = loaded

    # приоритет target: явный --target > env TARGET_URL > файл > дефолт
    effective_target = target or os.environ.get("TARGET_URL") or data.get("target")
    if effective_target:
        data["target"] = effective_target

    try:
        return RunnerConfig.model_validate(data)
    except Exception as exc:  # pydantic ValidationError → наша доменная ошибка
        raise ConfigError(f"некорректная конфигурация раннера: {exc}") from exc
