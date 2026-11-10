import json
from datetime import datetime, timezone

from rasp_scanner.adapters.reporters import ConsoleReporter, HtmlReporter, JsonReporter
from rasp_scanner.domain.enums import Severity, StepOutcome, StepType, Verdict
from rasp_scanner.domain.results import (
    CheckResult,
    RequestSnapshot,
    ResponseSnapshot,
    RunResult,
    ScenarioResult,
    StepResult,
)


def sample_run() -> RunResult:
    step = StepResult(
        name="B reads A's book", type=StepType.ATTACK, outcome=StepOutcome.VULNERABLE,
        as_role="user_b",
        request=RequestSnapshot("GET", "http://t/books/v1/x", headers={"Authorization": "***redacted***"}),
        response=ResponseSnapshot(200, body='{"secret":"leak"}', elapsed_ms=4.2),
        checks=[CheckResult("status", False, "status 200 ∈ [401, 403]")],
    )
    scenario = ScenarioResult(
        id="idor-books", name="IDOR", severity=Severity.HIGH, wstg="WSTG-ATHZ-04",
        verdict=Verdict.VULNERABLE, remediation="check ownership", tags=["idor"], steps=[step],
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    return RunResult(
        run_id="R1", target="http://t", scenarios=[scenario],
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_json_reporter_is_valid_and_complete():
    data = json.loads(JsonReporter().render(sample_run()))
    assert data["run_id"] == "R1"
    assert data["verdict"] == "vulnerable"
    assert data["summary"]["vulnerable"] == 1
    assert data["scenarios"][0]["steps"][0]["request"]["headers"]["Authorization"] == "***redacted***"


def test_console_reporter_mentions_verdict_and_summary():
    out = ConsoleReporter().render(sample_run())
    assert "VULNERABLE" in out
    assert "WSTG-ATHZ-04" in out
    assert "1 vulnerable" in out


def test_html_reporter_renders_without_template_leftovers():
    html = HtmlReporter().render(sample_run())
    assert "<!doctype html>" in html.lower()
    assert "IDOR" in html and "check ownership" in html
    assert "{{" not in html and "{%" not in html
