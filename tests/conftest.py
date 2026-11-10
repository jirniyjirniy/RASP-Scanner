"""Фикстуры pytest поверх тестовых дублёров из _doubles."""

from __future__ import annotations

import pytest

from _doubles import FixedClock, FixedRunId, Router


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def run_id() -> FixedRunId:
    return FixedRunId("scenrun")
