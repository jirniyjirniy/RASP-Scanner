import pytest

from rasp_scanner.domain.context import Context
from rasp_scanner.domain.errors import RenderError
from rasp_scanner.domain.rendering import Renderer


def ctx(**values):
    return Context(run_id="RID", env={"SECRET": "s3cr3t"}, values=values)


def test_whole_placeholder_preserves_type():
    r = Renderer(ctx(admin=True, count=3, items=[1, 2]))
    assert r.render("${admin}") is True          # bool сохраняется
    assert r.render("${count}") == 3             # int сохраняется
    assert r.render("${items}") == [1, 2]        # list сохраняется


def test_interpolation_in_text_becomes_string():
    r = Renderer(ctx())
    assert r.render("book-${run_id}") == "book-RID"


def test_bool_interpolated_as_lowercase():
    r = Renderer(ctx(flag=True))
    assert r.render("v=${flag}") == "v=true"     # не "True"


def test_nested_and_index_paths():
    r = Renderer(ctx(user={"name": "a"}, admins=[{"username": "root"}]))
    assert r.render("${user.name}") == "a"
    assert r.render("${admins.0.username}") == "root"


def test_env_and_run_id_builtins():
    r = Renderer(ctx())
    assert r.render("${env.SECRET}") == "s3cr3t"
    assert r.render("${run_id}") == "RID"


def test_unknown_variable_raises():
    r = Renderer(ctx())
    with pytest.raises(RenderError):
        r.render("${nope}")


def test_render_recurses_dict_and_list():
    r = Renderer(ctx(book="B", admin=True))
    out = r.render({"title": "${book}", "flags": ["${admin}", "x-${book}"]})
    assert out == {"title": "B", "flags": [True, "x-B"]}
