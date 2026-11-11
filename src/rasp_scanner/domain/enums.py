"""Перечисления домена.

Два вида:
  • входные (из YAML): Severity, HttpMethod, StepType — ограниченные наборы,
    опечатка в сценарии падает при валидации Pydantic;
  • результатные (вычисляются движком): StepOutcome, Verdict — язык вердиктов.
"""

from enum import Enum


# ── Входные (спек сценария) ──────────────────────────────────────────────────
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class StepType(str, Enum):
    SETUP = "setup"      # провал expect → ERROR (подготовка не удалась)
    ATTACK = "attack"    # провал expect → VULNERABLE, успех → SECURE


class BodyKind(str, Enum):
    """Способ кодирования тела запроса (и тела логина)."""
    JSON = "json"            # application/json
    FORM = "form"            # application/x-www-form-urlencoded
    MULTIPART = "multipart"  # multipart/form-data (поля + файлы)
    RAW = "raw"              # сырое тело строкой + явный Content-Type


# ── Результатные (язык вердиктов движка) ─────────────────────────────────────
class StepOutcome(str, Enum):
    """Чем закончился конкретный шаг."""
    PASSED = "passed"        # setup-шаг отработал как ожидалось
    SECURE = "secure"        # attack-шаг: сервер повёл себя безопасно
    VULNERABLE = "vulnerable"  # attack-шаг: защита не сработала
    ERROR = "error"          # setup-шаг не прошёл / сбой извлечения / сеть
    SKIPPED = "skipped"      # шаг не выполнялся (сценарий остановлен раньше)


class Verdict(str, Enum):
    """Итог по сценарию и по всему прогону."""
    SECURE = "secure"
    VULNERABLE = "vulnerable"
    ERROR = "error"

    @property
    def rank(self) -> int:
        # для свёртки: берём «худший» вердикт среди шагов/сценариев
        return {Verdict.SECURE: 0, Verdict.VULNERABLE: 1, Verdict.ERROR: 2}[self]
