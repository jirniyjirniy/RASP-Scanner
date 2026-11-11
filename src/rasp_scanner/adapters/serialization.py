"""RunResult → обычный dict (общая основа для JSON-отчёта и HTML-шаблона)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from ..domain.http import RequestBody
from ..domain.results import (
    CheckResult,
    RequestSnapshot,
    ResponseSnapshot,
    RunResult,
    ScenarioResult,
    StepResult,
)


def _val(x: Any) -> Any:
    if isinstance(x, Enum):
        return x.value
    if isinstance(x, datetime):
        return x.isoformat()
    return x


def body_to_dict(b: RequestBody | None) -> dict | None:
    if b is None:
        return None
    files = None
    if b.files:
        files = {
            name: {"filename": f.filename, "content": f.content, "content_type": f.content_type}
            for name, f in b.files.items()
        }
    return {"kind": _val(b.kind), "content": b.content, "files": files, "content_type": b.content_type}


def request_to_dict(r: RequestSnapshot | None) -> dict | None:
    if r is None:
        return None
    return {
        "method": r.method, "url": r.url, "headers": r.headers, "params": r.params,
        "body": body_to_dict(r.body), "cookies": r.cookies,
    }


def response_to_dict(r: ResponseSnapshot | None) -> dict | None:
    if r is None:
        return None
    return {
        "status_code": r.status_code, "headers": r.headers, "body": r.body,
        "elapsed_ms": round(r.elapsed_ms, 1), "cookies": r.cookies,
    }


def check_to_dict(c: CheckResult) -> dict:
    return {"kind": c.kind, "passed": c.passed, "message": c.message}


def step_to_dict(s: StepResult) -> dict:
    return {
        "name": s.name,
        "type": _val(s.type),
        "as_role": s.as_role,
        "outcome": _val(s.outcome),
        "error": s.error,
        "secure_if_hit": s.secure_if_hit,
        "duration_ms": round(s.duration_ms, 1),
        "request": request_to_dict(s.request),
        "response": response_to_dict(s.response),
        "checks": [check_to_dict(c) for c in s.checks],
        "saved": s.saved,
    }


def scenario_to_dict(s: ScenarioResult) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "severity": _val(s.severity),
        "wstg": s.wstg,
        "tags": s.tags,
        "description": s.description,
        "remediation": s.remediation,
        "verdict": _val(s.verdict),
        "error": s.error,
        "duration_ms": round(s.duration_ms, 1),
        "started_at": _val(s.started_at),
        "finished_at": _val(s.finished_at),
        "steps": [step_to_dict(st) for st in s.steps],
    }


def run_to_dict(run: RunResult) -> dict:
    return {
        "run_id": run.run_id,
        "target": run.target,
        "started_at": _val(run.started_at),
        "finished_at": _val(run.finished_at),
        "verdict": _val(run.verdict),
        "summary": run.summary,
        "scenarios": [scenario_to_dict(s) for s in run.scenarios],
    }
