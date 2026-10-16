import json

import pytest
from pydantic import ValidationError

from mtunifi.config import Settings
from mtunifi.main import main


@pytest.mark.parametrize(
    "url",
    [
        "http://user:secret@host/inform",
        "file:///inform",
        "http://host/api",
        "http://host/inform?key=secret",
    ],
)
def test_reject_unsafe_urls(url):
    with pytest.raises(ValidationError):
        Settings(inform_url=url)


def test_diagnostics_and_read_only_health(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MTUNIFI_STATE_DIR", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["mtunifi", "health"])
    assert main() == 2
    assert not list(tmp_path.iterdir())
    monkeypatch.setattr("sys.argv", ["mtunifi", "init"])
    assert main() == 0
    capsys.readouterr()
    monkeypatch.setattr("sys.argv", ["mtunifi", "diagnose"])
    assert main() == 0
    public = json.loads(capsys.readouterr().out)
    assert public["synthetic_ports"] == 8
    assert not public["controller_adoption_verified"]
    assert "authkey" not in public


def test_validate_scenario_is_offline_and_does_not_create_identity(tmp_path, monkeypatch, capsys):
    from pathlib import Path

    scenario = Path(__file__).resolve().parents[2] / "examples/synthetic-switch.json"
    monkeypatch.setenv("MTUNIFI_STATE_DIR", str(tmp_path / "unused"))
    monkeypatch.setenv("MTUNIFI_SYNTHETIC_FILE", str(scenario))
    monkeypatch.setattr("sys.argv", ["mtunifi", "validate-scenario"])
    assert main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "valid": True,
        "ports": 8,
        "clients": 3,
        "neighbors": 2,
    }
    assert not (tmp_path / "unused").exists()


def test_invalid_initial_scenario_does_not_create_identity_or_echo_values(
    tmp_path, monkeypatch, capsys
):
    scenario = tmp_path / "bad.json"
    scenario.write_text('{"DO-NOT-ECHO-AS-KEY":"DO-NOT-ECHO"}')
    monkeypatch.setenv("MTUNIFI_STATE_DIR", str(tmp_path / "unused"))
    monkeypatch.setenv("MTUNIFI_SYNTHETIC_FILE", str(scenario))
    monkeypatch.setattr("sys.argv", ["mtunifi", "run"])
    assert main() == 2
    output = capsys.readouterr().err
    assert "DO-NOT-ECHO" not in output
    assert json.loads(output)["reason"] == "Invalid synthetic scenario"
    assert {"path": "<unknown>", "error": "extra_forbidden"} in json.loads(output)["issues"]
    assert not (tmp_path / "unused").exists()


def test_device_version_override_is_validated():
    from mtunifi.config import Settings

    assert Settings(device_version="7.5.15.1234").device_version == "7.5.15.1234"
    with pytest.raises(ValueError):
        Settings(device_version="7.5; rm")


def test_device_mac_accepts_auto_and_unicast_only():
    from mtunifi.config import Settings

    assert Settings(device_mac="auto").device_mac == "auto"
    assert Settings(device_mac="00:00:5E:00:53:01").device_mac == "00:00:5e:00:53:01"
    with pytest.raises(ValueError):
        Settings(device_mac="01:00:5e:00:53:01")
