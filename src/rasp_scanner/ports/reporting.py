"""Порт репортера.

Движок отдаёт RunResult, репортеры превращают его в представление (JSON/HTML/
консоль). Добавить новый формат = новый адаптер, без изменений в движке.
"""

from __future__ import annotations

import abc

from ..domain.results import RunResult


class AbstractReporter(abc.ABC):
    #: расширение файла по умолчанию (json/html/txt)
    extension: str = "txt"

    @abc.abstractmethod
    def render(self, run: RunResult) -> str:
        """Построить строковое представление отчёта."""
