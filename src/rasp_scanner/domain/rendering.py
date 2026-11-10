"""Подстановка ${...} (Renderer).

Контракт формата (см. scenario-reference.yaml, блок RENDERER):
  • ${var} / ${var.field} / ${var.0.field} / ${env.NAME} / ${run_id}
  • СОХРАНЕНИЕ ТИПА: если значение целиком = одна переменная ("${admin}"),
    подставляется исходный тип (bool/int/list). Если переменная внутри текста
    ("book-${run_id}") — результат строка.
  • Неизвестная переменная → RenderError (не пустая строка).

Renderer рекурсивно проходит строки, словари и списки — поэтому одинаково
обрабатывает path, headers, params и json-тело запроса.
"""

from __future__ import annotations

import re
from typing import Any

from .context import Context

# ${ что-то-без-фигурных-скобок }
_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")
# строка, которая ЦЕЛИКОМ является одним плейсхолдером → сохраняем тип
_WHOLE = re.compile(r"^\$\{([^}]+)\}$")


class Renderer:
    def __init__(self, context: Context) -> None:
        self._ctx = context

    def render(self, value: Any) -> Any:
        """Рекурсивно подставляет ${...} в строках/словарях/списках."""
        if isinstance(value, str):
            return self._render_str(value)
        if isinstance(value, dict):
            return {k: self.render(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.render(v) for v in value]
        return value  # int/float/bool/None — подставлять нечего

    def _render_str(self, text: str) -> Any:
        whole = _WHOLE.match(text)
        if whole:
            # вся строка = одна переменная → возвращаем значение как есть (тип сохраняется)
            return self._ctx.resolve(whole.group(1).strip())
        # переменная(ые) внутри текста → интерполяция в строку
        return _PLACEHOLDER.sub(lambda m: self._stringify(self._ctx.resolve(m.group(1).strip())), text)

    @staticmethod
    def _stringify(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"   # не "True"/"False" из Python
        if value is None:
            return ""
        return str(value)
