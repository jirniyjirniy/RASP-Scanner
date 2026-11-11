"""Спецификация сценария (как он описан в YAML).

Это value-объекты домена: результат парсинга и валидации одного YAML-файла.
Один файл = один сценарий = один проверяемый вид уязвимости.

Модели оставлены на Pydantic сознательно: сама валидация (формат WSTG-ID,
"ровно один идентификатор у роли", `extra="forbid"`) — часть контракта формата,
а значит часть домена. Опечатка в сценарии падает здесь, а не в рантайме движка.
"""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import BodyKind, HttpMethod, Severity, StepType

# Формат идентификатора OWASP WSTG: WSTG-<КАТЕГОРИЯ>-<НОМЕР>, напр. WSTG-ATHZ-04
WSTG_PATTERN = re.compile(r"^WSTG-[A-Z]+-\d+$")


# ── Роль: один способ входа (идентификатор + пароль) ──
# username ИЛИ email: ровно один. Расширяется под новые механизмы позже.
class Role(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str | None = None   # = None делает поле необязательным (не просто "| None")
    email: str | None = None
    password: str

    @model_validator(mode="after")
    def exactly_one_identifier(self):
        has_user = self.username is not None
        has_email = self.email is not None
        if has_user == has_email:  # оба заданы или оба пусты
            raise ValueError("роль должна задавать ровно один идентификатор: username или email")
        return self


# ── save: длинная форма (поиск в списке) ──
class FindRule(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source: str = Field(alias="from")   # "from" — зарезервированное слово Python, нужен алиас
    where: dict[str, Any]
    get: str | None = None              # без get → сохраняется весь объект
    all: bool = False                   # True → всегда список (0 → [], иначе ERROR на 2+)


# save-значение: короткая форма (строка-путь) ИЛИ длинная (FindRule)
SaveRule = str | FindRule


# ── expect.vars: операторы проверки над переменной из контекста ──
class VarCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    eq: Any = None
    contains: Any = None
    not_contains: Any = None
    length: int | None = None


# ── expect / secure_if: один и тот же набор проверок ──
class Expect(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: list[int] | None = None
    json_body: dict[str, Any] = Field(default={}, alias="json")             # jsonpath → ожидаемое значение
    body_contains: str | None = None
    body_not_contains: str | None = None
    vars: dict[str, VarCheck] = {}

    @field_validator("status", mode="before")
    @classmethod
    def status_to_list(cls, v):
        # допускаем и status: 200, и status: [401, 403] → всегда список
        if v is None:
            return None
        return v if isinstance(v, list) else [v]


# ── Файл для multipart-тела (значения — шаблоны ${...}) ──
class FileSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    content: str = ""
    content_type: str | None = None


# ── Запрос ──
class Request(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    method: HttpMethod
    path: str                             # только путь, базовый адрес из --target
    headers: dict[str, str] = {}
    params: dict[str, Any] = {}           # query-параметры

    # ── тело: ровно одно из json/form/multipart/raw (валидатор следит) ──
    json_body: Any | None = Field(default=None, alias="json")    # application/json
    form: dict[str, Any] | None = None                           # x-www-form-urlencoded
    multipart: dict[str, Any] | None = None                      # multipart-поля
    files: dict[str, FileSpec] | None = None                     # multipart-файлы
    raw: str | None = None                                       # сырое тело строкой
    content_type: str | None = None                              # Content-Type для raw

    @model_validator(mode="after")
    def exactly_one_body(self):
        chosen = [
            name for name, val in (
                ("json", self.json_body), ("form", self.form),
                ("multipart", self.multipart), ("raw", self.raw),
            ) if val is not None
        ]
        if len(chosen) > 1:
            raise ValueError(f"в запросе можно задать только одно тело, а заданы: {', '.join(chosen)}")
        if self.files is not None and self.multipart is None:
            raise ValueError("files указываются вместе с multipart")
        if self.content_type is not None and self.raw is None:
            raise ValueError("content_type относится к raw-телу")
        return self

    def body_fields(self) -> tuple[BodyKind, Any, dict[str, FileSpec] | None, str | None] | None:
        """Выбранное тело в неотрендеренном виде: (kind, content, files, content_type)."""
        if self.json_body is not None:
            return (BodyKind.JSON, self.json_body, None, None)
        if self.form is not None:
            return (BodyKind.FORM, self.form, None, None)
        if self.multipart is not None:
            return (BodyKind.MULTIPART, self.multipart, self.files, None)
        if self.raw is not None:
            return (BodyKind.RAW, self.raw, None, self.content_type)
        return None


# ── Шаг ──
class Step(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str
    type: StepType
    as_role: str | None = Field(default=None, alias="as")  # "as" — keyword Python, обязателен алиас
    request: Request
    save: dict[str, SaveRule] = {}
    expect: Expect | None = None
    secure_if: Expect | None = None


# ── Сценарий: метаданные плоско + roles/vars/steps ──
class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str | None = None
    severity: Severity
    wstg: str
    tags: list[str] = []
    remediation: str | None = None

    roles: dict[str, Role] = {}           # произвольные имена → Role
    vars: dict[str, Any] = {}             # произвольные имена → любое значение (сохранение типа)
    steps: list[Step]

    @field_validator("wstg")
    @classmethod
    def wstg_format(cls, v: str) -> str:
        if not WSTG_PATTERN.match(v):
            raise ValueError(
                f"WSTG-ID должен быть вида WSTG-КАТЕГОРИЯ-НОМЕР (напр. WSTG-ATHZ-04), а не {v!r}"
            )
        return v
