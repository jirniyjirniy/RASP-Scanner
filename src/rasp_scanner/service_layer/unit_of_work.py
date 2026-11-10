"""Unit of Work прогона.

Адаптация паттерна из cosmicpython под инструмент без БД: UoW владеет ресурсом
прогона — HTTP-сессией (пул соединений) — и гарантирует её закрытие через
контекст-менеджер. Клиент создаётся фабрикой, поэтому в тестах подменяется на
поддельный без сети, а в проде — на httpx.
"""

from __future__ import annotations

import abc
from collections.abc import Callable

from ..ports.http import HttpClient


class AbstractRunUnitOfWork(abc.ABC):
    http: HttpClient

    def __enter__(self) -> "AbstractRunUnitOfWork":
        self.http = self._make_http()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @abc.abstractmethod
    def _make_http(self) -> HttpClient:
        ...

    def close(self) -> None:
        http = getattr(self, "http", None)
        if http is not None:
            http.close()


class RunUnitOfWork(AbstractRunUnitOfWork):
    def __init__(self, http_factory: Callable[[], HttpClient]) -> None:
        self._http_factory = http_factory

    def _make_http(self) -> HttpClient:
        return self._http_factory()
