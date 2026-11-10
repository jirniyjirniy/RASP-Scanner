from rasp_scanner.domain import assertions
from rasp_scanner.domain.context import Context
from rasp_scanner.domain.http import HttpResponse
from rasp_scanner.domain.scenario import Expect


def resp(status=200, text="", headers=None):
    return HttpResponse(status_code=status, headers=headers or {}, text=text)


def ctx(**values):
    return Context("RID", {}, values)


def evaluate(expect_dict, response, context):
    checks = assertions.evaluate(Expect.model_validate(expect_dict), response, context)
    return assertions.passed(checks), checks


def test_status_list():
    ok, _ = evaluate({"status": [401, 403]}, resp(403), ctx())
    assert ok
    ok, _ = evaluate({"status": 200}, resp(403), ctx())
    assert not ok


def test_json_path_equality_with_var():
    r = resp(text='{"data": {"username": "bob"}}')
    ok, _ = evaluate({"json": {"$.data.username": "${who}"}}, r, ctx(who="bob"))
    assert ok
    ok, _ = evaluate({"json": {"$.data.username": "eve"}}, r, ctx())
    assert not ok


def test_body_contains_and_not_contains():
    r = resp(text="secret-xyz leaked")
    ok, _ = evaluate({"body_contains": "leaked"}, r, ctx())
    assert ok
    ok, _ = evaluate({"body_not_contains": "${s}"}, r, ctx(s="secret-xyz"))
    assert not ok


def test_vars_checks():
    c = ctx(admins=[{"username": "root"}])
    ok, _ = evaluate({"vars": {"admins": {"length": 1}}}, resp(), c)
    assert ok
    ok, _ = evaluate({"vars": {"admins": {"length": 2}}}, resp(), c)
    assert not ok


def test_missing_json_path_fails_not_crashes():
    ok, checks = evaluate({"json": {"$.nope": "x"}}, resp(text="{}"), ctx())
    assert not ok and not checks[0].passed
