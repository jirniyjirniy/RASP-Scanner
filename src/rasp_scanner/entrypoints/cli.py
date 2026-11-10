"""CLI (Typer) — тонкий вход в приложение.

Разбирает аргументы, вызывает bootstrap (composition root) и сервисный слой,
печатает/сохраняет отчёты и выставляет код возврата для CI. Бизнес-логики здесь нет.
"""

from __future__ import annotations

import enum
from pathlib import Path
from typing import Optional

import typer

from ..adapters.reporters import ConsoleReporter
from ..bootstrap import bootstrap, make_reporter
from ..domain.enums import Verdict
from ..domain.errors import ScannerError
from ..service_layer.services import run_scenarios

app = typer.Typer(
    add_completion=False,
    help="RASP-Scanner — config-driven Security Test Runner для бизнес-логики REST API (OWASP WSTG).",
)

DEFAULT_SCENARIOS = Path("scenarios")


class FailOn(str, enum.Enum):
    vulnerable = "vulnerable"   # падаем на уязвимостях и ошибках (по умолчанию)
    error = "error"             # падаем только на ошибках выполнения
    never = "never"             # всегда код 0 (отчёт-онли)


class ColorWhen(str, enum.Enum):
    auto = "auto"               # цвет только в терминал
    always = "always"           # всегда (напр. для цветных логов CI)
    never = "never"             # без цвета

    def to_flag(self) -> bool | None:
        return {"auto": None, "always": True, "never": False}[self.value]


def _err(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


# цвет severity для list (Click сам снимет окраску при пайпе/редиректе)
_SEVERITY_FG = {
    "critical": typer.colors.BRIGHT_RED,
    "high": typer.colors.RED,
    "medium": typer.colors.YELLOW,
    "low": typer.colors.BLUE,
    "info": typer.colors.BRIGHT_BLACK,
}


@app.command()
def run(
    scenarios_dir: Path = typer.Option(DEFAULT_SCENARIOS, "--scenarios-dir", "-d", help="Каталог со сценариями (*.yaml)."),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Базовый URL стенда (иначе из --config/TARGET_URL/дефолта)."),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML-конфиг раннера (auth, timeout …)."),
    only: list[str] = typer.Option([], "--only", "-o", help="Запустить только сценарии с этими id (можно повторять)."),
    tags: list[str] = typer.Option([], "--tags", help="Только сценарии с пересечением по тегам."),
    report_json: Optional[Path] = typer.Option(None, "--report-json", help="Куда сохранить JSON-отчёт."),
    report_html: Optional[Path] = typer.Option(None, "--report-html", help="Куда сохранить HTML-отчёт."),
    fail_on: FailOn = typer.Option(FailOn.vulnerable, "--fail-on", help="Когда возвращать ненулевой код для CI."),
    color: ColorWhen = typer.Option(ColorWhen.auto, "--color", help="Цвет вывода: auto|always|never."),
) -> None:
    """Выполнить сценарии против стенда и сформировать отчёты."""
    try:
        app_ctx = bootstrap(scenarios_dir=scenarios_dir, config_path=config_path, target=target)
        scenarios = list(app_ctx.repository.filter(ids=only or None, tags=tags or None))
    except ScannerError as exc:
        _err(f"Не удалось подготовить запуск: {exc}")
        raise typer.Exit(code=2)

    if not scenarios:
        _err("Под фильтры не попал ни один сценарий.")
        raise typer.Exit(code=2)

    result = run_scenarios(
        scenarios,
        uow=app_ctx.uow,
        config=app_ctx.config,
        run_id_provider=app_ctx.run_id_provider,
        clock=app_ctx.clock,
        env=app_ctx.env,
    )

    color_flag = color.to_flag()
    typer.echo(ConsoleReporter(color=color_flag).render(result), color=color_flag)

    if report_json is not None:
        _write(report_json, make_reporter("json").render(result))
        typer.secho(f"JSON-отчёт: {report_json}", fg=typer.colors.BLUE, err=True)
    if report_html is not None:
        _write(report_html, make_reporter("html").render(result))
        typer.secho(f"HTML-отчёт: {report_html}", fg=typer.colors.BLUE, err=True)

    raise typer.Exit(code=_exit_code(result.verdict, fail_on))


@app.command()
def validate(
    scenarios_dir: Path = typer.Option(DEFAULT_SCENARIOS, "--scenarios-dir", "-d", help="Каталог со сценариями."),
) -> None:
    """Проверить, что все сценарии корректны (без обращения к сети)."""
    try:
        app_ctx = bootstrap(scenarios_dir=scenarios_dir)
        scenarios = app_ctx.repository.list()
    except ScannerError as exc:
        _err(f"Валидация не прошла: {exc}")
        raise typer.Exit(code=1)

    for s in scenarios:
        typer.secho(f"  ✓ {s.id:<28} {s.wstg:<14} {s.name}", fg=typer.colors.GREEN)
    typer.echo(f"\nОК: {len(scenarios)} сценариев валидны.")


@app.command(name="list")
def list_scenarios(
    scenarios_dir: Path = typer.Option(DEFAULT_SCENARIOS, "--scenarios-dir", "-d", help="Каталог со сценариями."),
) -> None:
    """Показать доступные сценарии и их метаданные."""
    try:
        app_ctx = bootstrap(scenarios_dir=scenarios_dir)
        scenarios = app_ctx.repository.list()
    except ScannerError as exc:
        _err(str(exc))
        raise typer.Exit(code=1)

    for s in scenarios:
        tags = f"  [{', '.join(s.tags)}]" if s.tags else ""
        sev = typer.style(f"{s.severity.value:<8}", fg=_SEVERITY_FG.get(s.severity.value), bold=s.severity.value == "critical")
        sid = typer.style(f"{s.id:<28}", bold=True)
        wstg = typer.style(f"{s.wstg:<14}", fg=typer.colors.CYAN)
        typer.echo(f"  {sid} {sev} {wstg} {s.name}{tags}")


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _exit_code(verdict: Verdict, fail_on: FailOn) -> int:
    if fail_on is FailOn.never:
        return 0
    if verdict is Verdict.ERROR:
        return 2
    if verdict is Verdict.VULNERABLE and fail_on is FailOn.vulnerable:
        return 1
    return 0


if __name__ == "__main__":
    app()
