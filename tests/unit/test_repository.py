from pathlib import Path

import pytest

from rasp_scanner.adapters.yaml_repository import ScenarioLoadError, YamlScenarioRepository
from rasp_scanner.domain.errors import ScenarioNotFoundError

SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "scenarios"


def test_loads_all_shipped_scenarios():
    repo = YamlScenarioRepository(SCENARIOS_DIR)
    ids = {s.id for s in repo.list()}
    assert {
        "idor-books", "mass-assignment-admin", "broken-auth-debug-leak",
        "workflow-bypass-password", "privilege-escalation-delete",
    } <= ids


def test_get_and_not_found():
    repo = YamlScenarioRepository(SCENARIOS_DIR)
    assert repo.get("idor-books").wstg == "WSTG-ATHZ-04"
    with pytest.raises(ScenarioNotFoundError):
        repo.get("does-not-exist")


def test_filter_by_tag():
    repo = YamlScenarioRepository(SCENARIOS_DIR)
    bola = {s.id for s in repo.filter(tags=["bola"])}
    assert "workflow-bypass-password" in bola
    assert "idor-books" not in bola          # у idor тега bola нет


def test_filter_by_ids():
    repo = YamlScenarioRepository(SCENARIOS_DIR)
    got = list(repo.filter(ids=["idor-books"]))
    assert len(got) == 1 and got[0].id == "idor-books"


def test_invalid_yaml_raises(tmp_path):
    (tmp_path / "broken.yaml").write_text("id: x\nsteps: [ : : :\n")
    with pytest.raises(ScenarioLoadError):
        YamlScenarioRepository(tmp_path).list()


def test_validation_error_names_file(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: x\nname: n\nseverity: high\nwstg: BAD\nsteps: []\n")
    with pytest.raises(ScenarioLoadError):
        YamlScenarioRepository(tmp_path).list()
