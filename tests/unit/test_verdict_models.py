import pytest
from pydantic import ValidationError

from rasp_scanner.domain.enums import StepOutcome, Verdict
from rasp_scanner.domain.scenario import Role, Scenario
from rasp_scanner.domain.verdict import fold_steps


def test_fold_precedence():
    assert fold_steps([StepOutcome.PASSED, StepOutcome.SECURE]) is Verdict.SECURE
    assert fold_steps([StepOutcome.VULNERABLE, StepOutcome.PASSED]) is Verdict.VULNERABLE
    # ERROR перебивает VULNERABLE
    assert fold_steps([StepOutcome.VULNERABLE, StepOutcome.ERROR]) is Verdict.ERROR
    assert fold_steps([]) is Verdict.SECURE


def test_role_requires_exactly_one_identifier():
    Role.model_validate({"username": "u", "password": "p"})          # ok
    with pytest.raises(ValidationError):
        Role.model_validate({"username": "u", "email": "e", "password": "p"})
    with pytest.raises(ValidationError):
        Role.model_validate({"password": "p"})


def test_scenario_rejects_bad_wstg_and_unknown_fields():
    base = {
        "id": "x", "name": "n", "severity": "high", "wstg": "WSTG-ATHZ-04",
        "steps": [{"name": "s", "type": "setup", "request": {"method": "GET", "path": "/"}}],
    }
    Scenario.model_validate(base)                                    # ok
    with pytest.raises(ValidationError):
        Scenario.model_validate({**base, "wstg": "not-wstg"})
    with pytest.raises(ValidationError):
        Scenario.model_validate({**base, "bogus": 1})               # extra=forbid
