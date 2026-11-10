"""Единый доступ к значениям внутри JSON-ответа.

Два синтаксиса в одном хелпере, потому что в формате сценария встречаются оба:
  • jsonpath:  "$.data.admin"      → полноценный jsonpath-ng (ключи expect.json)
  • точечный:  "auth_token",
               "data.username"     → короткая форма save и token_path

Правило выбора: путь, начинающийся с "$", считаем jsonpath; иначе — точечный
проход по dict/list (числовой сегмент = индекс списка).
"""

from __future__ import annotations

from typing import Any

from jsonpath_ng.ext import parse as _jsonpath_parse

_MISSING = object()


def _walk_dotted(data: Any, path: str) -> Any:
    """Проход `a.b.0.c`: ключ словаря или индекс списка. Нет пути → _MISSING."""
    current = data
    for seg in path.split("."):
        if isinstance(current, dict):
            if seg not in current:
                return _MISSING
            current = current[seg]
        elif isinstance(current, (list, tuple)):
            if not seg.lstrip("-").isdigit():
                return _MISSING
            idx = int(seg)
            if not (-len(current) <= idx < len(current)):
                return _MISSING
            current = current[idx]
        else:
            return _MISSING
    return current


def query_all(data: Any, path: str) -> list[Any]:
    """Все совпадения. jsonpath может вернуть несколько, точечный путь — 0 или 1."""
    if path.startswith("$"):
        return [m.value for m in _jsonpath_parse(path).find(data)]
    found = _walk_dotted(data, path)
    return [] if found is _MISSING else [found]


def query_first(data: Any, path: str, default: Any = _MISSING) -> Any:
    """Первое совпадение или default. Если default не задан и совпадений нет — KeyError."""
    matches = query_all(data, path)
    if matches:
        return matches[0]
    if default is _MISSING:
        raise KeyError(path)
    return default


def exists(data: Any, path: str) -> bool:
    return bool(query_all(data, path))
