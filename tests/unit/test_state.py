import json
import stat

import pytest
from pydantic import ValidationError

from mtunifi.emulator import apply_response
from mtunifi.protocol import ProtocolError
from mtunifi.storage import Store

KEY = "1234567890abcdef1234567890abcdef"  # Synthetic fixture, not a device secret.


def test_identity_persistence_and_permissions(tmp_path):
    store = Store(tmp_path)
    with store.lock():
        first = store.load_or_create()
        apply_response(first, {"_type": "setparam", "mgmt_cfg": f"authkey={KEY}\nuse_aes_gcm=1"})
        store.save(first)
    second = store.load_or_create()
    assert first == second
    assert second.authkey.get_secret_value() == KEY
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert KEY not in json.dumps(second.public())
    assert KEY not in repr(second)


def test_corrupt_state_not_replaced(tmp_path):
    store = Store(tmp_path)
    store.path.write_text('{"authkey":"secret-do-not-log"}')
    with pytest.raises(ValidationError):
        store.load_or_create()
    assert "secret-do-not-log" in store.path.read_text()


def test_exclusive_ownership(tmp_path):
    with Store(tmp_path).lock(), pytest.raises(RuntimeError), Store(tmp_path).lock():
        pass


def test_independent_devices(tmp_path):
    stores = [Store(tmp_path / name) for name in ("one", "two")]
    identities = []
    for store in stores:
        with store.lock():
            identities.append(store.load_or_create())
    assert identities[0].mac != identities[1].mac
    apply_response(identities[0], {"_type": "setparam", "mgmt_cfg": f"authkey={KEY}"})
    assert identities[1].authkey is None


def test_state_transitions_and_redaction(tmp_path, caplog):
    state = Store(tmp_path).load_or_create()
    with caplog.at_level("INFO"):
        apply_response(state, {"_type": "noop"})
        assert state.phase == "factory"
        apply_response(
            state,
            {
                "_type": "setparam",
                "mgmt_cfg": f"authkey={KEY}",
                "system_cfg": "password=HIDDEN",
                "cfgversion": "abc",
            },
        )
        assert state.phase == "key-received"
        assert apply_response(state, {"_type": "noop", "interval": 30}) == 30
        assert state.phase == "exchanging"
        for kind in ("cmd", "upgrade", "reboot", "secret-unknown"):
            apply_response(state, {"_type": kind, "cmd": "HIDDEN"})
    assert state.cfgversion == "abc"
    assert state.authkey.get_secret_value() == KEY
    assert KEY not in caplog.text
    assert "HIDDEN" not in caplog.text
    assert "secret-unknown" not in caplog.text


def test_controller_reset_only_clears_adoption_metadata(tmp_path):
    state = Store(tmp_path).load_or_create()
    state.controller_url = "http://controller:8080/inform"
    mac = state.mac
    apply_response(
        state,
        {"_type": "setparam", "mgmt_cfg": f"authkey={KEY}\nuse_aes_gcm=1", "cfgversion": "old"},
    )
    assert apply_response(state, {"_type": "setdefault"}) == 1
    assert state.mac == mac and state.controller_url == "http://controller:8080/inform"
    assert state.phase == "factory" and state.authkey is None and state.cfgversion == ""
    assert state.encryption == "cbc"


@pytest.mark.parametrize(
    "mgmt",
    [
        "authkey=bad",
        "authkey=" + "ab" * 16 + "\nuse_aes_gcm=bad",
        "authkey=ba86f2bbe107c7c57eb5f2690775c712",
    ],
)
def test_invalid_provisioning_is_transactional(tmp_path, mgmt):
    state = Store(tmp_path).load_or_create()
    before = state.model_copy(deep=True)
    with pytest.raises(ProtocolError):
        apply_response(state, {"_type": "setparam", "mgmt_cfg": mgmt})
    assert state == before


@pytest.mark.parametrize("interval", [-1, 0, 9999999, "bad", True, float("inf")])
def test_invalid_intervals(tmp_path, interval):
    assert (
        apply_response(Store(tmp_path).load_or_create(), {"_type": "noop", "interval": interval})
        is None
    )


def test_configured_mac_identity_is_explicit_and_bound(tmp_path):
    store = Store(tmp_path)
    with store.lock():
        state = store.load_or_create("00:00:5E:00:53:10")
    assert (state.mac, state.mac_source) == ("00:00:5e:00:53:10", "configured")
    assert store.load_or_create("00:00:5e:00:53:10") == state
    with pytest.raises(ValueError, match="Configured MAC differs"):
        store.load_or_create("00:00:5e:00:53:11")
    with pytest.raises(ValidationError):
        type(state)(mac="00:00:5e:00:53:10")  # A physical MAC is never a synthetic identity.
