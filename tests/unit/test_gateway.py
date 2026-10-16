from dataclasses import replace

import pytest
from pydantic import ValidationError

from mtunifi.config import Settings
from mtunifi.gateway import gateway_snapshot, wan_addresses
from mtunifi.snapshot import DeviceHealth, DeviceSnapshot, WANObservation
from mtunifi.storage import State, StateBindingError


def address(value="198.51.100.2/24", interface="ether1", **fields):
    return {
        "address": value,
        "interface": interface,
        "disabled": "false",
        "invalid": "false",
        **fields,
    }


def test_address_scope_disabled_invalid_and_ambiguity_never_select_arbitrary_ip():
    assert wan_addresses(None, "ether1") == ((), "unavailable")
    assert wan_addresses([], "ether1") == ((), "observed")
    assert wan_addresses([address(), address(interface="bridge")], "ether1") == (
        ("198.51.100.2/24",),
        "observed",
    )
    assert wan_addresses(
        [address(), address(disabled="true"), address(invalid="true")], "ether1"
    ) == (("198.51.100.2/24",), "observed")
    assert wan_addresses([address(**{"actual-interface": "vlan10"})], "ether1") == ((), "observed")
    assert wan_addresses(
        [address(interface="ether1", **{"actual-interface": "pppoe-out1"})], "pppoe-out1"
    ) == (("198.51.100.2/24",), "observed")
    candidates, status = wan_addresses([address(), address("203.0.113.5/32")], "ether1")
    assert len(candidates) == 2 and status == "ambiguous"
    for bad in ("garbage", "198.51.100.2", "0.0.0.0/0", "127.0.0.1/8", "224.0.0.1/24", "::1/128"):
        assert wan_addresses([address(), address(bad)], "ether1")[1] == "invalid"


def test_adapter_uses_ugw3_wan_alias_large_counters_unknown_fields_and_synthetic_identity():
    health = DeviceHealth(
        "7.24.4", 321, cpu_percent=10, memory_total_bytes=100, memory_free_bytes=80
    )
    wan = WANObservation(
        "pppoe-out1",
        "pppoe-out",
        True,
        True,
        2**53 + 123,
        42,
        ip="198.51.100.2",
        netmask="255.255.255.255",
    )
    snapshot = DeviceSnapshot(health, (), wan=wan)
    body = gateway_snapshot(snapshot, "02:00:00:00:00:11")
    assert "port_table" not in body and "lldp_table" not in body
    assert body["config_port_table"] == [{"ifname": "eth0", "name": "wan", "type": "wan"}]
    assert body["uplink"] == "eth0" and body["uptime"] == 321
    (entry,) = body["if_table"]
    assert entry["rx_bytes"] == 2**53 + 123 and entry["tx_bytes"] == 42
    assert entry["mac"] == "02:00:00:00:00:11" and entry["netmask"] == "255.255.255.255"
    assert "speed" not in entry and "full_duplex" not in entry and "latency" not in entry
    down = gateway_snapshot(replace(snapshot, wan=replace(wan, up=False)), "")
    assert down["if_table"][0]["speed"] == 0 and down["if_table"][0]["rx_bytes"] == 2**53 + 123
    assert "mac" not in down["if_table"][0]


def test_gateway_default_wan_and_no_port_map_or_adopted_switch_reclassification():
    settings = Settings(
        profile="ugw3-experimental",
        telemetry_source="routeros",
        routeros_host="192.168.0.249",
        routeros_user="reader",
        routeros_password_file="/run/password",
    )
    assert settings.routeros_map_file is None and settings.routeros_wan_interface == "ether1"
    for name in ("", "ether1\n", "x" * 129):
        with pytest.raises(ValidationError):
            Settings(**(settings.model_dump() | {"routeros_wan_interface": name}))
    with pytest.raises(ValidationError):
        Settings(profile="ugw3-experimental")
    old = State(mac="02:00:00:00:00:11", profile="us8-experimental")
    with pytest.raises(StateBindingError):
        old.bind("ugw3-experimental", "192.168.0.249")
    assert old.profile == "us8-experimental" and old.authkey is None


def test_second_wan_is_exported_as_eth2_with_its_own_mac():
    health = DeviceHealth("7.24.5", 10)
    wan = WANObservation(
        "ether1", "ether", True, True, 1, 2, 1000, True, "198.51.100.2", "255.255.255.0"
    )
    wan2 = WANObservation("ether5", "ether", True, False, 3, 4)
    body = gateway_snapshot(DeviceSnapshot(health, (), wan=wan, wan2=wan2), "02:00:00:00:00:ff")
    assert body["config_port_table"] == [
        {"ifname": "eth0", "name": "wan", "type": "wan"},
        {"ifname": "eth2", "name": "wan2", "type": "wan"},
    ]
    first, second = body["if_table"]
    assert (first["name"], first["up"]) == ("eth0", True)
    assert (second["name"], second["up"], second["speed"]) == ("eth2", False, 0)
    assert second["mac"] == "02:00:00:00:00:00" and body["uplink"] == "eth0"
