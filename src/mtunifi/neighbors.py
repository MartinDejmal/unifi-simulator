"""Neighbor-cache evidence, without inferring switches from forwarding entries."""

from dataclasses import replace

from mtunifi.clients import mac_address
from mtunifi.routeros_api import RouterOSError
from mtunifi.routeros_values import text, uptime_seconds
from mtunifi.snapshot import DeviceSnapshot, NeighborInventory, NeighborObservation


def tokens(value: str | None) -> tuple[str, ...]:
    safe = text(value, 4096)
    if not safe:
        return ()
    result = tuple(part.strip() for part in safe.split(","))
    if len(result) > 128 or any(not text(part) for part in result):
        return ()
    return tuple(sorted(set(result)))


def collect_neighbors(
    snapshot: DeviceSnapshot,
    rows: list[dict] | None,
    *,
    local_macs: tuple[str | None, ...] = (),
    relaxed: bool = False,
    mac_aliases: dict[str, str] | None = None,
) -> DeviceSnapshot:
    """`relaxed` also accepts MNDP/CDP, merged-protocol rows and bond members (opt-in)."""
    accepted = {"lldp", "cdp", "mndp"} if relaxed else {"lldp"}
    if rows is None:
        return replace(snapshot, neighbors=NeighborInventory(None))
    local = {mac_address(m) for m in local_macs} - {None}
    local.update(p.mac.lower() for p in snapshot.ports if mac_address(p.mac))
    ports = {p.name: p for p in snapshot.ports}
    # Logical aliases may accompany the receive port (e.g. ether2,bridge-lan).
    # They never identify a physical member by themselves.
    bridges = {i.name for i in snapshot.logical_interfaces if i.kind == "bridge"}
    bridge_members = {
        (m.interface, m.bridge) for m in snapshot.bridge_members or () if m.enabled is not False
    }
    bonded = {
        member
        for interface in snapshot.logical_interfaces
        if interface.kind == "bonding"
        for member in interface.members or ()
    }
    bonds = {i.name for i in snapshot.logical_interfaces if i.kind == "bonding"}
    aliases = bridges | bonds if relaxed else bridges
    unknown_bond_members = any(
        i.kind == "bonding" and i.members is None for i in snapshot.logical_interfaces
    )
    observations = []
    invalid = excluded = 0
    for row in rows:
        interfaces = tokens(row.get("interface"))
        mac = mac_address(row.get("mac-address"))
        if mac in local:
            excluded += 1
            continue
        if mac is not None and mac_aliases:
            mac = mac_aliases.get(mac, mac)
        raw_protocols = tokens(row.get("discovered-by"))
        protocols = tuple(sorted({p.lower() for p in raw_protocols})) or ("unknown",)
        identity = text(row.get("identity"))
        remote_port = text(row.get("interface-name"), 64)
        description = text(row.get("system-description"))
        age = None
        if row.get("age"):
            try:
                age = uptime_seconds(row["age"])
            except RouterOSError:
                pass
        candidates = [ports[i] for i in interfaces if i in ports]
        reason = "eligible"
        port = candidates[0] if len(candidates) == 1 else None
        if not interfaces or (mac is None and identity is None):
            reason = "invalid-row"
            invalid += 1
        elif port is None or any(i not in ports and i not in aliases for i in interfaces):
            reason = "unresolved-local-interface"
        elif any(
            alias in bridges
            and (port.name, alias) not in bridge_members
            # A bonded member joins the bridge through its bond.
            and not (relaxed and port.name in bonded)
            for alias in interfaces
        ):
            reason = "unverified-bridge-alias"
        elif port.name in bonded and not relaxed:
            reason = "bond-member"
        elif unknown_bond_members:
            reason = "bond-membership-unknown"
        elif not port.enabled or not port.up:
            reason = "local-port-down"
        elif not accepted & set(protocols):
            reason = "protocol-not-lldp"
        elif not set(protocols) <= accepted:
            # Merged cache fields cannot be attributed to one advertised protocol.
            reason = "merged-protocols"
        elif mac is None:
            reason = "remote-mac-unknown"
        elif remote_port is None:
            reason = "remote-port-unknown"
        observations.append(
            NeighborObservation(
                interfaces,
                protocols,
                mac,
                identity,
                remote_port,
                description,
                age,
                port.port_idx if port else None,
                reason,
            )
        )
    # Identical repeated cache rows do not create multiple links. Any differing LLDP
    # advertisements on a slot are ambiguous; retain evidence without choosing one.
    deduplicated = {}
    for n in observations:
        key = replace(n, age_seconds=None)
        previous = deduplicated.get(key)
        if previous is None or (
            n.age_seconds is not None
            and (previous.age_seconds is None or n.age_seconds < previous.age_seconds)
        ):
            deduplicated[key] = n
    observations = list(deduplicated.values())
    by_port: dict[int, set[tuple]] = {}
    for n in observations:
        if n.port_idx is not None and accepted & set(n.protocols):
            by_port.setdefault(n.port_idx, set()).add(
                (n.mac, n.remote_port, n.identity, n.system_description)
            )
    observations = [
        replace(n, export_reason="ambiguous-local-port")
        if n.export_reason == "eligible" and len(by_port.get(n.port_idx, ())) > 1
        else n
        for n in observations
    ]
    # A malformed inventory is unknown, not an authoritative partial/empty table.
    warnings = (*snapshot.warnings, "neighbors:invalid-row") if invalid else snapshot.warnings
    return replace(
        snapshot,
        neighbors=NeighborInventory(
            tuple(observations), excluded_local=excluded, invalid_rows=invalid
        ),
        warnings=warnings,
    )
