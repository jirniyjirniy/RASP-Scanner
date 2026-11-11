"""HTTP value-объекты домена.

Отделяем СПЕК запроса (`scenario.Request`: путь + шаблоны ${...}, ещё не готов
к отправке) от МАТЕРИАЛИЗОВАННОГО запроса (`HttpRequest`: абсолютный URL,
подставленные значения, вставленный токен). Движок работает с первым, адаптер
HTTP — со вторым. Благодаря этому домен не знает про httpx.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any

from .enums import BodyKind


@dataclass(frozen=True, slots=True)
class FilePart:
    """Один файловый элемент multipart-тела (материализованный, уже отрендеренный)."""

    filename: str
    content: str = ""
    content_type: str | None = None


@dataclass(frozen=True, slots=True)
class RequestBody:
    """Тело запроса, независимое от способа кодирования.

    content: dict для json/form/multipart (поля), str для raw.
    files:   только для multipart (имя поля → FilePart).
    content_type: для raw (или явное переопределение).
    """

    kind: BodyKind
    content: Any = None
    files: dict[str, FilePart] | None = None
    content_type: str | None = None


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """Готовый к отправке запрос. Создаёт движок, исполняет адаптер HttpClient."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    body: RequestBody | None = None
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Ответ сервера в форме, независимой от HTTP-клиента."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 0.0
    cookies: dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        """Распарсенное тело. Бросает, если тело не JSON — вызывающий решает, важно ли это."""
        return _json.loads(self.text)

    def json_or_none(self) -> Any | None:
        try:
            return _json.loads(self.text)
        except (ValueError, TypeError):
            return None
