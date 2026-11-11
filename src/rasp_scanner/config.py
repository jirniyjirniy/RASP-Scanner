"""Конфигурация раннера (НЕ сценария).

Здесь живёт то, что общее для стенда, а не для конкретной уязвимости: базовый
адрес и МЕХАНИКА ВХОДА. Именно поэтому один сценарий гоняется против любого
стенда — как логиниться и как подставлять учётку вынесено сюда.

Схема auth намеренно гибкая, под реальные сайты (не только VAmPI):
  • type: login   — логин телом любого типа (json/form/raw), токен берётся из
                    JSON-тела / заголовка / cookie / regex, опц. session-cookies;
  • type: static  — без логина: готовый токен/API-key из env в заголовок/query;
  • type: basic   — HTTP Basic из учётки роли;
  • type: none    — без авторизации.
Плюс опциональный CSRF pre-flow. Дефолты воспроизводят поведение под VAmPI,
поэтому запуск без --config не меняется.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .domain.enums import BodyKind, HttpMethod
from .domain.errors import ConfigError
from .domain.scenario import FileSpec


class BodySpec(BaseModel):
    """Тело логина/CSRF-fetch. Тот же набор типов, что и у тела шага."""

    model_config = ConfigDict(extra="forbid")

    type: BodyKind = BodyKind.JSON
    fields: dict[str, Any] = {}              # json | form | multipart (поля)
    raw: str | None = None                   # raw
    content_type: str | None = None          # raw
    files: dict[str, FileSpec] | None = None  # multipart

    def body_fields(self):
        if self.type is BodyKind.RAW:
            return (BodyKind.RAW, self.raw or "", None, self.content_type)
        if self.type is BodyKind.MULTIPART:
            return (BodyKind.MULTIPART, self.fields, self.files, None)
        return (self.type, self.fields, None, None)   # json | form


class TokenSpec(BaseModel):
    """Откуда брать токен/значение из ответа (логина или CSRF-fetch)."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["json", "header", "cookie", "regex"] = "json"
    path: str = "auth_token"     # source=json: точечный путь или $.jsonpath
    header: str | None = None    # source=header: имя заголовка ответа
    cookie: str | None = None    # source=cookie: имя cookie из Set-Cookie
    regex: str | None = None     # source=regex: шаблон с группой 1 = значение

    @model_validator(mode="after")
    def field_for_source(self):
        need = {"header": self.header, "cookie": self.cookie, "regex": self.regex}
        if self.source in need and not need[self.source]:
            raise ValueError(f"для token.source={self.source} нужно задать поле {self.source!r}")
        return self


class InjectRule(BaseModel):
    """Как подставить значение (${token}) в запрос: заголовок/cookie/query."""

    model_config = ConfigDict(extra="forbid")

    into: Literal["header", "cookie", "query"] = "header"
    name: str = "Authorization"
    template: str = "Bearer ${token}"


class FetchSpec(BaseModel):
    """Запрос предварительной выборки (CSRF pre-flow)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    method: HttpMethod = HttpMethod.GET
    path: str = "/"
    headers: dict[str, str] = {}
    params: dict[str, Any] = {}


def _default_login_body() -> BodySpec:
    return BodySpec(fields={"username": "${username}", "password": "${password}"})


class LoginConfig(BaseModel):
    """Как залогинить роль и где взять токен из ответа."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    method: HttpMethod = HttpMethod.POST
    path: str = "/users/v1/login"
    body: BodySpec = Field(default_factory=_default_login_body)
    token: TokenSpec = Field(default_factory=TokenSpec)
    session: bool = False        # нести cookies ответа логина на запросы роли


class BasicConfig(BaseModel):
    """HTTP Basic. Учётка берётся из роли (username/email + password)."""

    model_config = ConfigDict(extra="forbid")

    header: str = "Authorization"


class StaticConfig(BaseModel):
    """Авторизация без логина: готовые значения из env в заголовок/query."""

    model_config = ConfigDict(extra="forbid")

    inject: list[InjectRule] = []


class CsrfConfig(BaseModel):
    """Опциональный CSRF pre-flow: выбрать страницу → достать токен → подставлять."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    fetch: FetchSpec = Field(default_factory=FetchSpec)
    token: TokenSpec = Field(default_factory=lambda: TokenSpec(source="cookie", cookie="XSRF-TOKEN"))
    inject: InjectRule = Field(
        default_factory=lambda: InjectRule(into="header", name="X-XSRF-TOKEN", template="${token}")
    )


def _default_inject() -> list[InjectRule]:
    return [InjectRule()]   # Authorization: Bearer ${token}


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["login", "static", "basic", "none"] = "login"
    login: LoginConfig = Field(default_factory=LoginConfig)
    inject: list[InjectRule] = Field(default_factory=_default_inject)
    basic: BasicConfig | None = None
    static: StaticConfig | None = None
    csrf: CsrfConfig | None = None


class RunnerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = "http://localhost:5001"
    auth: AuthConfig = Field(default_factory=AuthConfig)
    timeout: float = 15.0
    verify_tls: bool = True
    follow_redirects: bool = False   # вкл. для session-логинов, отвечающих 30x
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
