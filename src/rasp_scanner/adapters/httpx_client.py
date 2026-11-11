"""Боевой адаптер HTTP на httpx.

Единственное место в коде, которое знает про httpx. Переводит доменный
HttpRequest (включая тело любого типа) в вызов httpx и ответ httpx обратно
в доменный HttpResponse.
"""

from __future__ import annotations

import httpx

from ..domain.enums import BodyKind
from ..domain.http import HttpRequest, HttpResponse, RequestBody
from ..ports.http import HttpClient


class HttpxClient(HttpClient):
    def __init__(
        self, *, timeout: float = 15.0, verify_tls: bool = True, follow_redirects: bool = False
    ) -> None:
        self._client = httpx.Client(timeout=timeout, verify=verify_tls, follow_redirects=follow_redirects)

    def send(self, request: HttpRequest) -> HttpResponse:
        headers = dict(request.headers)
        kwargs: dict = {
            "params": request.params or None,
            "cookies": request.cookies or None,
        }
        kwargs.update(_body_kwargs(request.body, headers))
        kwargs["headers"] = headers or None

        response = self._client.request(request.method, request.url, **kwargs)
        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            elapsed_ms=response.elapsed.total_seconds() * 1000,
            cookies=dict(response.cookies),
        )

    def close(self) -> None:
        self._client.close()


def _body_kwargs(body: RequestBody | None, headers: dict[str, str]) -> dict:
    """RequestBody → kwargs для httpx. Content-Type json/form/multipart ставит сам httpx;
    для raw домешиваем его в headers (не затирая явный заголовок шага)."""
    if body is None:
        return {}
    if body.kind is BodyKind.JSON:
        return {"json": body.content}
    if body.kind is BodyKind.FORM:
        return {"data": body.content}
    if body.kind is BodyKind.MULTIPART:
        kwargs: dict = {"files": _build_files(body.files)}
        if body.content:
            kwargs["data"] = body.content   # обычные поля рядом с файлами
        return kwargs
    if body.kind is BodyKind.RAW:
        if body.content_type and not _has_header(headers, "content-type"):
            headers["Content-Type"] = body.content_type
        return {"content": body.content}
    return {}


def _has_header(headers: dict[str, str], name: str) -> bool:
    return any(k.lower() == name for k in headers)


def _build_files(files: dict | None) -> dict:
    """{имя поля → FilePart} → формат httpx files=: (filename, content, content_type)."""
    out: dict = {}
    for field_name, part in (files or {}).items():
        out[field_name] = (part.filename, part.content, part.content_type)
    return out
