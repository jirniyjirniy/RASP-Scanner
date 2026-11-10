"""Репортеры: JSON, HTML, консоль. Каждый — отдельный адаптер порта."""

from __future__ import annotations

import json
from importlib.resources import files

from jinja2 import Environment, select_autoescape

from ..domain.enums import Verdict
from ..domain.results import RunResult
from ..ports.reporting import AbstractReporter
from . import serialization

# символы-маркеры вердикта для консоли
_MARK = {Verdict.SECURE: "✓ SECURE", Verdict.VULNERABLE: "✗ VULNERABLE", Verdict.ERROR: "! ERROR"}


class JsonReporter(AbstractReporter):
    extension = "json"

    def render(self, run: RunResult) -> str:
        return json.dumps(serialization.run_to_dict(run), ensure_ascii=False, indent=2)


class ConsoleReporter(AbstractReporter):
    extension = "txt"

    def render(self, run: RunResult) -> str:
        lines: list[str] = []
        lines.append(f"Target : {run.target}")
        lines.append(f"Run    : {run.run_id}")
        lines.append("")
        for s in run.scenarios:
            lines.append(f"  {_MARK[s.verdict]:<14} [{s.severity.value:<8}] {s.wstg:<14} {s.id} — {s.name}")
            for st in s.steps:
                for c in st.failed_checks:
                    lines.append(f"       └─ {st.name}: {c.message}")
            if s.error:
                lines.append(f"       └─ ERROR: {s.error}")
        summary = run.summary
        lines.append("")
        lines.append(
            f"Summary: {summary['total']} scenarios — "
            f"{summary['vulnerable']} vulnerable, {summary['secure']} secure, {summary['error']} error"
        )
        lines.append(f"Verdict: {_MARK[run.verdict]}")
        return "\n".join(lines)


class HtmlReporter(AbstractReporter):
    extension = "html"

    def __init__(self) -> None:
        template_text = files("rasp_scanner.templates").joinpath("report.html.j2").read_text("utf-8")
        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        self._template = env.from_string(template_text)

    def render(self, run: RunResult) -> str:
        return self._template.render(run=serialization.run_to_dict(run))
