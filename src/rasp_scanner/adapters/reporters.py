"""Репортеры: JSON, HTML, консоль. Каждый — отдельный адаптер порта."""

from __future__ import annotations

import json
import os
import sys
from importlib.resources import files

from jinja2 import Environment, select_autoescape

from ..domain.enums import Severity, Verdict
from ..domain.results import RunResult
from ..ports.reporting import AbstractReporter
from . import serialization

# текст и ANSI-коды вердикта (SGR): bold + цвет
_VERDICT_TEXT = {Verdict.SECURE: "✓ SECURE", Verdict.VULNERABLE: "✗ VULNERABLE", Verdict.ERROR: "! ERROR"}
_VERDICT_CODE = {Verdict.SECURE: "1;32", Verdict.VULNERABLE: "1;91", Verdict.ERROR: "1;33"}
_SEVERITY_CODE = {
    Severity.CRITICAL: "1;91", Severity.HIGH: "31", Severity.MEDIUM: "33",
    Severity.LOW: "34", Severity.INFO: "90",
}


class _Painter:
    """Оборачивает текст в SGR-коды, либо отдаёт как есть (когда цвет выключен)."""

    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def __call__(self, text: str, codes: str) -> str:
        return f"\x1b[{codes}m{text}\x1b[0m" if self.on else text


def _should_color() -> bool:
    # цвет только в настоящий терминал и если не выставлен NO_COLOR
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class JsonReporter(AbstractReporter):
    extension = "json"

    def render(self, run: RunResult) -> str:
        return json.dumps(serialization.run_to_dict(run), ensure_ascii=False, indent=2)


class ConsoleReporter(AbstractReporter):
    extension = "txt"

    def __init__(self, color: bool | None = None) -> None:
        # None → автоопределение по TTY; паддинг считаем по «голому» тексту до окраски
        self._color = _should_color() if color is None else color

    def render(self, run: RunResult) -> str:
        p = _Painter(self._color)
        out: list[str] = []
        out.append(p("Target", "1;2") + "   " + p(run.target, "36"))
        out.append(p("Run", "1;2") + "      " + run.run_id)
        out.append("")

        for s in run.scenarios:
            mark = p(f"{_VERDICT_TEXT[s.verdict]:<12}", _VERDICT_CODE[s.verdict])
            sev = p(f"[{s.severity.value:<8}]", _SEVERITY_CODE[s.severity])
            out.append(f"  {mark}  {sev} " + p(f"{s.wstg:<14}", "36") + " " + p(s.id, "1") + f" — {s.name}")
            for st in s.steps:
                for c in st.failed_checks:
                    out.append("       " + p("└─ ", "90") + p(f"{st.name}: ", "2") + c.message)
            if s.error:
                out.append("       " + p("└─ ERROR: ", "33") + s.error)

        summary = run.summary
        out.append("")
        out.append(
            p("Summary", "1;2") + f"  {summary['total']} scenarios — "
            + p(f"{summary['vulnerable']} vulnerable", "91") + ", "
            + p(f"{summary['secure']} secure", "32") + ", "
            + p(f"{summary['error']} error", "33")
        )
        out.append(p("Verdict", "1;2") + "  " + p(_VERDICT_TEXT[run.verdict], _VERDICT_CODE[run.verdict]))
        return "\n".join(out)


class HtmlReporter(AbstractReporter):
    extension = "html"

    def __init__(self) -> None:
        template_text = files("rasp_scanner.templates").joinpath("report.html.j2").read_text("utf-8")
        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        self._template = env.from_string(template_text)

    def render(self, run: RunResult) -> str:
        return self._template.render(run=serialization.run_to_dict(run))
