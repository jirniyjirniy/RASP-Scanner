"""Материализация тела запроса: (спек тела) + Renderer → RequestBody.

Один помощник для двух мест — тела шага (engine) и тела логина (AuthManager).
На вход — кортеж из `.body_fields()` (kind, content-шаблон, files-шаблон, content_type),
который одинаково отдают и `scenario.Request`, и `config.BodySpec`.
"""

from __future__ import annotations

from typing import Any

from .enums import BodyKind
from .http import FilePart, RequestBody
from .rendering import Renderer

BodyFields = tuple[BodyKind, Any, dict | None, str | None]


def materialize(fields: BodyFields | None, renderer: Renderer) -> RequestBody | None:
    """Рендерит ${...} в выбранном теле и собирает RequestBody (или None, если тела нет)."""
    if fields is None:
        return None
    kind, content_tpl, files_tpl, content_type_tpl = fields
    content = renderer.render(content_tpl)
    files = None
    if files_tpl:
        files = {
            name: FilePart(
                filename=str(renderer.render(f.filename)),
                content=str(renderer.render(f.content)),
                content_type=str(renderer.render(f.content_type)) if f.content_type else None,
            )
            for name, f in files_tpl.items()
        }
    content_type = str(renderer.render(content_type_tpl)) if content_type_tpl else None
    return RequestBody(kind=kind, content=content, files=files, content_type=content_type)
