"""Контекст одного прогона сценария.

Единое пространство имён для ${...}: пользовательские vars + значения из save +
встроенные (`run_id`, `env`). Живёт в пределах одного сценария, общий для всех шагов.
Резолвит точечные пути вида `admins.0.username`.
"""

from __future__ import annotations

from typing import Any

from .errors import RenderError

_MISSING = object()


class Context:
    def __init__(
        self,
        run_id: str,
        env: dict[str, str] | None = None,
        values: dict[str, Any] | None = None,
    ) -> None:
        self.run_id = run_id
        self._env = dict(env or {})
        self._values: dict[str, Any] = dict(values or {})

    # ── запись (vars на старте, save по ходу) ──
    def set(self, name: str, value: Any) -> None:
        self._values[name] = value

    def snapshot(self) -> dict[str, Any]:
        """Копия пользовательских переменных — для отчёта по шагу."""
        return dict(self._values)

    def derive(self, values: dict[str, Any]) -> "Context":
        """Дочерний контекст: тот же run_id/env, но свой набор переменных.

        Нужен для рендера тела логина и шаблона инъекции токена, где в ходу
        временные имена (${username}, ${password}, ${token}), не относящиеся
        к переменным сценария.
        """
        return Context(self.run_id, self._env, values)

    # ── чтение по пути ──
    def resolve(self, path: str) -> Any:
        """`${path}` → значение. Неизвестное имя/кривой путь → RenderError."""
        head, _, tail = path.partition(".")

        if head == "run_id":
            root = self.run_id
            if tail:
                raise RenderError(f"run_id — строка, вложенный путь ${{{path}}} недопустим")
            return root

        if head == "env":
            if not tail:
                raise RenderError("используйте ${env.ИМЯ}, а не ${env}")
            if tail not in self._env:
                raise RenderError(f"переменная окружения {tail!r} не задана (путь ${{{path}}})")
            return self._env[tail]

        if head not in self._values:
            raise RenderError(
                f"неизвестная переменная ${{{head}}}"
                + (f" (в пути ${{{path}}})" if tail else "")
                + f". Доступны: {', '.join(sorted(self._values)) or '—'}"
            )

        value = self._values[head]
        return self._walk(value, tail, path) if tail else value

    def _walk(self, value: Any, dotted: str, full_path: str) -> Any:
        current = value
        for seg in dotted.split("."):
            if isinstance(current, dict):
                if seg not in current:
                    raise RenderError(f"нет ключа {seg!r} в пути ${{{full_path}}}")
                current = current[seg]
            elif isinstance(current, (list, tuple)):
                if not seg.lstrip("-").isdigit():
                    raise RenderError(f"ожидался индекс списка, а не {seg!r} в ${{{full_path}}}")
                idx = int(seg)
                if not (-len(current) <= idx < len(current)):
                    raise RenderError(f"индекс {idx} вне списка (длина {len(current)}) в ${{{full_path}}}")
                current = current[idx]
            else:
                raise RenderError(
                    f"нельзя взять {seg!r} у значения типа {type(current).__name__} в ${{{full_path}}}"
                )
        return current
