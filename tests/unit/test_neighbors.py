from dataclasses import replace

import pytest

from mtunifi.neighbors import collect_neighbors
from mtunifi.snapshot import (
    BridgeMember,
    ClientInventory,
    DeviceHealth,
    DeviceSnapshot,
    LogicalInterface,
    PhysicalPort,
    PortPoE,
    unifi_snapshot,
)

A = "00:11:22:33:44:55"
B = "00:11:22:33:44:66"
LOCAL = "dc:2c:6e:00:00:01"


def row(**kwargs):
    return {
        "interface": "ether2",
        "mac-address": A,
        "identity": "upstream",
        "interface-name": "Gi1/0/8",
        "discovered-by": "lldp",
        "age": "1m2s",
        **kwargs,
    }


def scene(rows, **kwargs):
    snapshot = DeviceSnapshot(
        DeviceHealth("7.24.4", 100),
        tuple(
            PhysicalPort(i, f"ether{i}", None, LOCAL, i != 3, i != 3, 1000, True, True, 0, 0)
            for i in range(1, 4)
        ),
        (
            LogicalInterface("br", "bridge"),
            LogicalInterface("bond", "bonding", members=("ether1",)),
        ),
        (BridgeMember("ether2", "br", 1, True, None, True),),
    )
    return collect_neighbors(snapshot, rows, **kwargs)


def test_reported_lldp_identity_port_and_age_no_fdb_topology():
    snapshot = scene([row(), row(age="3s")])
    (n,) = snapshot.neighbors.observations
    assert n.mac == A and n.age_seconds == 3 and n.protocols == ("lldp",)
    assert n.evidence == "routeros-neighbor-cache" and n.certainty == "reported"
    (wire,) = unifi_snapshot(snapshot)["lldp_table"]
    assert wire == {
        "chassis_id": A,
        "chassis_descr": "upstream",
        "local_port_idx": 2,
        "local_port_name": "ether2",
        "port_id": "Gi1/0/8",
        "is_wired": True,
    }
    aliases = scene([row(), row(interface="ether2,br")])
    assert len(aliases.neighbors.observations) == 2
    assert len(unifi_snapshot(aliases)["lldp_table"]) == 1


@pytest.mark.parametrize(
    "fields,reason",
    [
        ({"discovered-by": "mndp"}, "protocol-not-lldp"),
        ({"discovered-by": "cdp"}, "protocol-not-lldp"),
        ({"discovered-by": ""}, "protocol-not-lldp"),
        ({"discovered-by": "mndp,lldp"}, "merged-protocols"),
        ({"interface-name": ""}, "remote-port-unknown"),
        ({"interface-name": "a\nb"}, "remote-port-unknown"),
        ({"mac-address": "01:11:22:33:44:55"}, "remote-mac-unknown"),
        ({"interface": "br"}, "unresolved-local-interface"),
        ({"interface": "bond"}, "unresolved-local-interface"),
        ({"interface": "unmapped"}, "unresolved-local-interface"),
        ({"interface": "ether1,ether2"}, "unresolved-local-interface"),
        ({"interface": "ether2,bond"}, "unresolved-local-interface"),
        ({"interface": "ether1"}, "bond-member"),
        ({"interface": "ether3"}, "local-port-down"),
        ({"interface": "ether3,br"}, "unverified-bridge-alias"),
    ],
)
def test_incomplete_or_unattributable_evidence_stays_diagnostic(fields, reason):
    snapshot = scene([row(**fields)])
    assert unifi_snapshot(snapshot)["lldp_table"] == []
    assert snapshot.neighbors.observations[0].export_reason == reason


def test_bridge_alias_needs_observed_membership_and_does_not_create_a_port():
    snapshot = scene([row(interface="br,ether2")])
    assert unifi_snapshot(snapshot)["lldp_table"][0]["local_port_idx"] == 2
    assert snapshot.neighbors.observations[0].interfaces == ("br", "ether2")
    snapshot = replace(snapshot, ports=tuple(replace(p, up=False) for p in snapshot.ports))
    # Fresh normalization uses current link status, not the previously cached eligibility.
    snapshot = collect_neighbors(snapshot, [row(interface="br,ether2")])
    assert unifi_snapshot(snapshot)["lldp_table"] == []
    snapshot = replace(snapshot, logical_interfaces=(LogicalInterface("bond", "bonding"),))
    snapshot = collect_neighbors(snapshot, [row()])
    assert snapshot.neighbors.observations[0].export_reason == "bond-membership-unknown"
    assert unifi_snapshot(snapshot)["lldp_table"] == []


def test_multiple_or_conflicting_advertisements_do_not_choose_a_direct_link():
    snapshot = scene([row(), row(**{"mac-address": B})])
    assert len(snapshot.neighbors.observations) == 2
    assert all(n.export_reason == "ambiguous-local-port" for n in snapshot.neighbors.observations)
    assert unifi_snapshot(snapshot)["lldp_table"] == []
    snapshot = scene([row(), row(identity="conflicting")])
    assert unifi_snapshot(snapshot)["lldp_table"] == []


def test_unknown_empty_invalid_and_local_exclusion():
    assert "lldp_table" not in unifi_snapshot(scene(None))
    assert unifi_snapshot(scene([]))["lldp_table"] == []
    snapshot = scene([row(), row(interface="")])
    assert "lldp_table" not in unifi_snapshot(snapshot)
    assert snapshot.neighbors.invalid_rows == 1 and snapshot.warnings
    assert len(snapshot.neighbors.observations) == 2  # Partial evidence stays diagnostic only.
    snapshot = scene(
        [row(**{"mac-address": LOCAL}), row(**{"mac-address": B})], local_macs=(B.upper(),)
    )
    assert snapshot.neighbors.excluded_local == 2
    assert unifi_snapshot(snapshot)["lldp_table"] == []


def test_missing_description_and_age_not_invented():
    snapshot = scene([row(identity="", age="bad")])
    assert snapshot.neighbors.observations[0].age_seconds is None
    assert "chassis_descr" not in unifi_snapshot(snapshot)["lldp_table"][0]


def test_relaxed_mode_exports_mndp_merged_and_bond_member_neighbors_with_aliases():
    rows = [
        row(**{"discovered-by": "cdp,mndp"}),
        row(interface="bond,br,ether1", **{"mac-address": B, "interface-name": "Port 9"}),
    ]
    strict = scene(rows)
    assert {n.export_reason for n in strict.neighbors.observations} == {
        "protocol-not-lldp",
        "unresolved-local-interface",
    }
    relaxed = scene(rows, relaxed=True, mac_aliases={A: "00:00:5e:00:53:10"})
    assert {(n.port_idx, n.mac, n.export_reason) for n in relaxed.neighbors.observations} == {
        (2, "00:00:5e:00:53:10", "eligible"),
        (1, B, "eligible"),
    }
    assert len(unifi_snapshot(relaxed)["lldp_table"]) == 2


def test_relaxed_neighbor_macs_fill_mac_table_once_for_downlinks():
    rows = [
        row(**{"discovered-by": "cdp,mndp"}),
        row(interface="bond,br,ether1", **{"mac-address": B, "interface-name": "Port 9"}),
    ]
    snapshot = scene(rows, relaxed=True)
    snapshot = replace(snapshot, wired=ClientInventory((), {"fdb": "available"}))
    ports = {p["port_idx"]: p for p in unifi_snapshot(snapshot, neighbor_macs=True)["port_table"]}
    assert [e["mac"] for e in ports[1]["mac_table"]] == [B]
    assert [e["mac"] for e in ports[2]["mac_table"]] == [A]
    plain = {p["port_idx"]: p for p in unifi_snapshot(snapshot)["port_table"]}
    assert plain[1]["mac_table"] == [] and plain[2]["mac_table"] == []
    uplinked = replace(
        snapshot,
        ports=tuple(replace(p, is_uplink=p.port_idx == 2) for p in snapshot.ports),
    )
    ports = {p["port_idx"]: p for p in unifi_snapshot(uplinked, neighbor_macs=True)["port_table"]}
    assert ports[2]["mac_table"] == []  # the uplink neighbor is the parent


def test_bond_members_are_reported_as_a_lag_led_by_the_lowest_port():
    snapshot = replace(
        scene([]),
        logical_interfaces=(LogicalInterface("bond", "bonding", members=("ether2", "ether1")),),
    )
    ports = {p["port_idx"]: p for p in unifi_snapshot(snapshot, report_lag=True)["port_table"]}
    assert ports[1]["op_mode"] == "aggregate" and ports[1]["aggregate_members"] == [1, 2]
    assert ports[2]["aggregated_by"] == 1 and ports[2]["lag_idx"] == ports[1]["lag_idx"] == 1
    assert "op_mode" not in unifi_snapshot(snapshot)["port_table"][0]


def test_poe_state_is_reported_like_a_unifi_poe_switch():
    snapshot = scene([])
    ports = list(snapshot.ports)
    ports[0] = replace(ports[0], poe=PortPoE("auto-on", "powered-on", 48.6, 157.0, 7.6))
    ports[1] = replace(ports[1], poe=PortPoE("off", "disabled"))
    table = unifi_snapshot(replace(snapshot, ports=tuple(ports)))["port_table"]
    assert table[0]["poe_enable"] and table[0]["poe_power"] == "7.60"
    assert table[0]["poe_current"] == "157.00" and table[0]["poe_mode"] == "auto"
    assert table[1]["poe_mode"] == "off" and table[1]["poe_power"] == "0.00"
    assert "port_poe" not in table[2]
