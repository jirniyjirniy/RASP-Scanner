"""Редакция секретов в результатах прогона.

Отчёт по определению показывает сырые запросы/ответы — а значит рискует вынести
наружу пароли (тела логина, дамп /_debug, сохранённые учётки, тексты проверок).
Здесь — единственное место, где секреты вычищаются, ПЕРЕД тем как RunResult
попадёт в любой репортёр. Поэтому JSON, HTML и консоль защищены разом.

Две независимые стратегии, дополняющие друг друга:
  • по ИМЕНИ ключа  — значение под ключом вида *password*/*token*/*secret*
    заменяется на маркер. Ловит ЧУЖИЕ, заранее неизвестные секреты (сид-пароли
    стенда из дампа, токены в теле ответа).
  • по ЗНАЧЕНИЮ      — известные нам секреты (пароли ролей, секретные vars)
    вырезаются как подстрока где угодно, включая свободный текст сообщений
    (`тело НЕ содержит 'Pwned-...'`), пути и не-JSON тела.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Iterable

from .enums import BodyKind
from .http import RequestBody
from .results import RequestSnapshot, ResponseSnapshot, StepResult

#: чем заменяем секрет (тот же маркер, что у редакции заголовков в движке)
REDACTED = "***redacted***"

#: подстроки имени ключа, значение под которым считаем секретом
_SENSITIVE_KEY_PARTS = (
    "password", "passwd", "pwd", "secret", "token",
    "apikey", "api_key", "authorization", "credential", "private_key",
)

#: заголовки, значение которых прячем целиком (имя секрет не раскрывает, значение — да)
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}

#: "<ключ с секретным именем>": "<значение>" в сыром/обрезанном JSON-теле,
#: где структурный разбор не применить (тело — строка, возможно усечённая)
_JSON_SECRET_RE = re.compile(
    r'("[^"]*(?:' + "|".join(_SENSITIVE_KEY_PARTS) + r')[^"]*"\s*:\s*)"[^"]*"',
    re.IGNORECASE,
)


def is_sensitive_key(key: Any) -> bool:
    """Имя ключа говорит, что под ним секрет?"""
    k = str(key).lower()
    return any(part in k for part in _SENSITIVE_KEY_PARTS)


def _redact_cookies(cookies: dict[str, str]) -> dict[str, str]:
    """Cookie по природе секрет (сессия/токен) — прячем значение, имя оставляем."""
    return {name: REDACTED for name in cookies}


class Redactor:
    """Вычищает секреты из снимков шага. Без I/O, домен его создаёт и применяет."""

    def __init__(self, secret_values: Iterable[str] | None = None) -> None:
        # длинные значения сначала — чтобы замена не рвала более длинный секрет
        self._secrets = sorted(
            {s for s in (secret_values or ()) if isinstance(s, str) and s},
            key=len,
            reverse=True,
        )

    # ── применение к результату шага (мутирует StepResult на месте) ──
    def scrub_step(self, step: StepResult) -> None:
        if step.request is not None:
            step.request = self._redact_request(step.request)
        if step.response is not None:
            step.response = self._redact_response(step.response)
        if step.checks:
            step.checks = [replace(c, message=self.redact_text(c.message)) for c in step.checks]
        if step.saved:
            step.saved = self.redact_structured(step.saved)
        if step.error:
            step.error = self.redact_text(step.error)

    def _redact_request(self, r: RequestSnapshot) -> RequestSnapshot:
        return replace(
            r,
            headers=self._redact_headers(r.headers),
            params=self.redact_structured(r.params),
            body=self._redact_body_obj(r.body),
            cookies=_redact_cookies(r.cookies),
        )

    def _redact_response(self, r: ResponseSnapshot) -> ResponseSnapshot:
        return replace(
            r,
            headers=self._redact_headers(r.headers),
            body=self.redact_body(r.body),
            cookies=_redact_cookies(r.cookies),
        )

    def _redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Чувствительные заголовки прячем по имени, остальные чистим по известным значениям."""
        out: dict[str, str] = {}
        for key, value in headers.items():
            out[key] = REDACTED if key.lower() in _SENSITIVE_HEADERS else self.redact_text(value)
        return out

    def _redact_body_obj(self, body: RequestBody | None) -> RequestBody | None:
        if body is None:
            return None
        if body.kind is BodyKind.RAW:
            content = self.redact_body(body.content) if isinstance(body.content, str) else body.content
        else:
            content = self.redact_structured(body.content)
        files = None
        if body.files:
            files = {name: replace(f, content=self.redact_body(f.content)) for name, f in body.files.items()}
        return replace(body, content=content, files=files)

    # ── универсальные операции ──
    def redact_structured(self, obj: Any) -> Any:
        """dict/list/скаляр: значение под секретным ключом → маркер, строки чистим по значению."""
        return self._walk(obj, sensitive=False)

    def _walk(self, obj: Any, *, sensitive: bool) -> Any:
        if sensitive:
            return REDACTED
        if isinstance(obj, dict):
            return {k: self._walk(v, sensitive=is_sensitive_key(k)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(v, sensitive=False) for v in obj]
        if isinstance(obj, str):
            return self._scrub_known(obj)
        return obj

    def redact_body(self, text: str) -> str:
        """Тело ответа — строка: чистим секретные поля по регекспу + известные значения."""
        if not isinstance(text, str) or not text:
            return text
        text = _JSON_SECRET_RE.sub(lambda m: f'{m.group(1)}"{REDACTED}"', text)
        return self._scrub_known(text)

    def redact_text(self, text: str) -> str:
        """Свободный текст (сообщение проверки, ошибка): только по известным значениям."""
        if not isinstance(text, str):
            return text
        return self._scrub_known(text)

    def _scrub_known(self, text: str) -> str:
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, REDACTED)
        return text
