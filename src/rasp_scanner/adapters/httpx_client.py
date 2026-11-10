"""Боевой адаптер HTTP на httpx.

Единственное место в коде, которое знает про httpx. Переводит доменный
HttpRequest в вызов httpx и ответ httpx обратно в доменный HttpResponse.
"""

from __future__ import annotations

import httpx

from ..domain.http import HttpRequest, HttpResponse
from ..ports.http import HttpClient


class HttpxClient(HttpClient):
    def __init__(self, *, timeout: float = 15.0, verify_tls: bool = True) -> None:
        self._client = httpx.Client(timeout=timeout, verify=verify_tls, follow_redirects=False)

    def send(self, request: HttpRequest) -> HttpResponse:
        kwargs: dict = {"headers": request.headers or None, "params": request.params or None}
        if request.json_body is not None:
            kwargs["json"] = request.json_body

        response = self._client.request(request.method, request.url, **kwargs)
        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            elapsed_ms=response.elapsed.total_seconds() * 1000,
        )

    def close(self) -> None:
        self._client.close()
