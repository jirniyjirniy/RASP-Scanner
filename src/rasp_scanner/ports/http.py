"""Порт HTTP-клиента.

Движок зависит только от этого интерфейса, а не от httpx. Благодаря этому его
тесты гоняют сценарии через поддельный клиент без сети, а продовый адаптер
(httpx) подменяется в composition root.
"""

from __future__ import annotations

import abc

from ..domain.http import HttpRequest, HttpResponse


class HttpClient(abc.ABC):
    @abc.abstractmethod
    def send(self, request: HttpRequest) -> HttpResponse:
        """Отправить готовый запрос и вернуть ответ. Сетевой сбой → поднять исключение."""

    def close(self) -> None:  # не абстрактный: не всем адаптерам нужно освобождать ресурс
        """Освободить ресурсы (соединения). По умолчанию — ничего."""
