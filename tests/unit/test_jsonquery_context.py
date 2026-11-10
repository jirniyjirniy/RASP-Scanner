import pytest

from rasp_scanner.domain import jsonquery
from rasp_scanner.domain.context import Context
from rasp_scanner.domain.errors import RenderError

DATA = {"auth_token": "T", "data": {"username": "bob"}, "users": [{"n": 1}, {"n": 2}]}


def test_dotted_path():
    assert jsonquery.query_first(DATA, "auth_token") == "T"
    assert jsonquery.query_first(DATA, "data.username") == "bob"


def test_jsonpath_path():
    assert jsonquery.query_first(DATA, "$.data.username") == "bob"
    assert jsonquery.query_all(DATA, "$.users[*].n") == [1, 2]


def test_missing_returns_default_or_raises():
    assert jsonquery.query_first(DATA, "missing", default=None) is None
    with pytest.raises(KeyError):
        jsonquery.query_first(DATA, "missing")


def test_context_resolve_errors_are_informative():
    c = Context("RID", {}, {"x": [1]})
    with pytest.raises(RenderError):
        c.resolve("x.5")          # индекс вне списка
    with pytest.raises(RenderError):
        c.resolve("env.NOPE")     # нет env-переменной


def test_context_derive_shares_run_id_and_env():
    c = Context("RID", {"E": "1"}, {"a": 1})
    child = c.derive({"token": "tok"})
    assert child.resolve("run_id") == "RID"
    assert child.resolve("env.E") == "1"
    assert child.resolve("token") == "tok"
