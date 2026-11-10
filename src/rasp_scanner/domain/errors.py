"""Доменные ошибки.

Все они означают «сценарий не смог корректно выполниться» → движок превращает их
в StepOutcome.ERROR с внятным сообщением, а не в тихий None или падение процесса.
"""


class ScannerError(Exception):
    """Базовая ошибка инструмента."""


class RenderError(ScannerError):
    """Не удалось подставить ${...}: неизвестная переменная или кривой путь."""


class ExtractionError(ScannerError):
    """save не смог достать значение из ответа (нет поля, 0 или 2+ совпадений)."""


class AuthError(ScannerError):
    """Не удалось залогинить роль (нет токена в ответе, логин не прошёл)."""


class ConfigError(ScannerError):
    """Некорректная конфигурация раннера."""


class ScenarioNotFoundError(ScannerError):
    """Запрошен сценарий, которого нет в репозитории."""
