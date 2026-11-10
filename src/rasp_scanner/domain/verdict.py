"""Свёртка исходов шагов в вердикт сценария.

Контракт (scenario-reference.yaml, блок ВЕРДИКТ):
    есть хоть один ERROR      → ERROR
    иначе есть хоть VULNERABLE → VULNERABLE
    иначе                      → SECURE

SKIPPED/PASSED/SECURE на вердикт сами по себе не влияют; «пусто» → SECURE.
"""

from __future__ import annotations

from collections.abc import Iterable

from .enums import StepOutcome, Verdict


def fold_steps(outcomes: Iterable[StepOutcome]) -> Verdict:
    seen = set(outcomes)
    if StepOutcome.ERROR in seen:
        return Verdict.ERROR
    if StepOutcome.VULNERABLE in seen:
        return Verdict.VULNERABLE
    return Verdict.SECURE
