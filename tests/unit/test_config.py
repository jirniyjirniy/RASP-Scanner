import pytest

from rasp_scanner.config import load_config
from rasp_scanner.domain.errors import ConfigError


def test_defaults_target_and_login(monkeypatch):
    monkeypatch.delenv("TARGET_URL", raising=False)
    cfg = load_config()
    assert cfg.base_url.startswith("http")
    assert cfg.auth.type == "login"
    assert cfg.auth.login.path == "/users/v1/login"
    assert cfg.auth.login.token.source == "json"
    assert cfg.auth.login.token.path == "auth_token"
    assert cfg.auth.inject[0].template == "Bearer ${token}"


def test_explicit_target_wins_over_env(monkeypatch):
    monkeypatch.setenv("TARGET_URL", "http://from-env:1")
    cfg = load_config(target="http://explicit:2")
    assert cfg.base_url == "http://explicit:2"


def test_env_target_used_when_no_explicit(monkeypatch):
    monkeypatch.setenv("TARGET_URL", "http://from-env:1")
    assert load_config().base_url == "http://from-env:1"


def test_yaml_config_file(tmp_path, monkeypatch):
    monkeypatch.delenv("TARGET_URL", raising=False)   # ambient env не должен перебивать файл
    f = tmp_path / "cfg.yaml"
    f.write_text("target: http://box:9\ntimeout: 3\nauth:\n  login:\n    token:\n      path: data.jwt\n")
    cfg = load_config(f)
    assert cfg.base_url == "http://box:9"
    assert cfg.timeout == 3
    assert cfg.auth.login.token.path == "data.jwt"


def test_missing_config_file_raises():
    with pytest.raises(ConfigError):
        load_config("/no/such/file.yaml")


def test_bad_config_shape_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("- not\n- a\n- mapping\n")
    with pytest.raises(ConfigError):
        load_config(f)
