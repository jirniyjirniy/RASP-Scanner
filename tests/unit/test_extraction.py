import pytest

from rasp_scanner.domain.context import Context
from rasp_scanner.domain.errors import ExtractionError
from rasp_scanner.domain.extraction import extract
from rasp_scanner.domain.rendering import Renderer
from rasp_scanner.domain.scenario import FindRule

USERS = {
    "users": [
        {"username": "a", "admin": False, "password": "pa"},
        {"username": "b", "admin": True, "password": "pb"},
        {"username": "c", "admin": True, "password": "pc"},
    ]
}


def rnd(**values):
    return Renderer(Context("RID", {}, values))


def test_short_form_path():
    assert extract("users.0.username", USERS, rnd()) == "a"


def test_short_form_missing_raises():
    with pytest.raises(ExtractionError):
        extract("users.0.nope", USERS, rnd())


def test_find_single_match_get_field():
    rule = FindRule.model_validate({"from": "users", "where": {"username": "a"}, "get": "password"})
    assert extract(rule, USERS, rnd()) == "pa"


def test_find_zero_matches_raises():
    rule = FindRule.model_validate({"from": "users", "where": {"username": "zzz"}})
    with pytest.raises(ExtractionError):
        extract(rule, USERS, rnd())


def test_find_multiple_without_all_raises():
    rule = FindRule.model_validate({"from": "users", "where": {"admin": True}})
    with pytest.raises(ExtractionError):
        extract(rule, USERS, rnd())


def test_find_all_returns_list_even_when_empty():
    rule = FindRule.model_validate({"from": "users", "where": {"username": "zzz"}, "all": True})
    assert extract(rule, USERS, rnd()) == []


def test_find_all_returns_whole_objects():
    rule = FindRule.model_validate({"from": "users", "where": {"admin": True}, "all": True})
    out = extract(rule, USERS, rnd())
    assert [o["username"] for o in out] == ["b", "c"]


def test_where_value_is_rendered():
    rule = FindRule.model_validate({"from": "users", "where": {"username": "${target}"}, "get": "password"})
    assert extract(rule, USERS, rnd(target="c")) == "pc"
