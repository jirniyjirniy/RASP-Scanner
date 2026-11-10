"""Извлечение значений из ответа (save / Extractors).

Две формы (см. scenario-reference.yaml):
  • короткая — строка-путь внутрь JSON ("auth_token", "data.username");
  • длинная  — FindRule: поиск элемента(ов) в СПИСКЕ по условию where.

Семантика длинной формы без all:
    0 совпадений → ошибка, 1 → значение, 2+ → ошибка ("уточни условие или all: true").
С all: true результат ВСЕГДА список (0 → [], 1 → [x], 2+ → [...]).

Поля rule (source/where/get) прогоняются через Renderer, поэтому в них можно
использовать ${...}. Пути не найдены → ExtractionError (не тихий None).
"""

from __future__ import annotations

from typing import Any

from . import jsonquery
from .errors import ExtractionError
from .rendering import Renderer
from .scenario import FindRule, SaveRule

_MISSING = object()


def extract(rule: SaveRule, data: Any, renderer: Renderer) -> Any:
    if isinstance(rule, str):
        return _extract_path(rule, data, renderer)
    return _extract_find(rule, data, renderer)


def _extract_path(path_tpl: str, data: Any, renderer: Renderer) -> Any:
    path = renderer.render(path_tpl)
    value = jsonquery.query_first(data, path, default=_MISSING)
    if value is _MISSING:
        raise ExtractionError(f"путь {path!r} не найден в ответе")
    return value


def _extract_find(rule: FindRule, data: Any, renderer: Renderer) -> Any:
    source = renderer.render(rule.source)
    items = jsonquery.query_first(data, source, default=_MISSING)
    if items is _MISSING:
        raise ExtractionError(f"список {source!r} не найден в ответе")
    if not isinstance(items, list):
        raise ExtractionError(f"{source!r} — не список (а {type(items).__name__}), поиск невозможен")

    where = {k: renderer.render(v) for k, v in rule.where.items()}
    get = renderer.render(rule.get) if rule.get else None

    matches = [_project(item, get, source) for item in items if _matches(item, where)]

    if rule.all:
        return matches  # тип задаёт автор (all), а не данные
    if not matches:
        raise ExtractionError(f"в {source!r} нет элемента по условию {where}")
    if len(matches) > 1:
        raise ExtractionError(
            f"в {source!r} найдено {len(matches)} совпадений по {where}: уточни условие или добавь all: true"
        )
    return matches[0]


def _matches(item: Any, where: dict[str, Any]) -> bool:
    if not isinstance(item, dict):
        return False
    return all(item.get(key, _MISSING) == expected for key, expected in where.items())


def _project(item: Any, get: str | None, source: str) -> Any:
    if get is None:
        return item  # весь объект — чтобы работал ${x.0.field}
    value = jsonquery.query_first(item, get, default=_MISSING)
    if value is _MISSING:
        raise ExtractionError(f"у найденного в {source!r} элемента нет поля {get!r}")
    return value
