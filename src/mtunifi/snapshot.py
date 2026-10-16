"""Vendor-neutral observations and profile-sized UniFi switch mapping."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DeviceHealth:
    version: str
    uptime_seconds: int
    identity: str | None = None
    cpu_percent: int | None = None
    memory_total_bytes: int | None = None
    memory_free_bytes: int | None = None
    board: str | None = None


@dataclass(frozen=True)
class PhysicalPort:
    port_idx: int
    name: str
    default_name: str | None
    mac: str | None
    enabled: bool
    up: bool
    speed_mbps: int | None
    full_duplex: bool | None
    autoneg: bool | None
    rx_bytes: int
    tx_bytes: int
    is_uplink: bool = False
    poe: "PortPoE | None" = None


@dataclass(frozen=True)
class PortPoE:
    """Observed RouterOS PoE-out state; unknown values stay None."""

    mode: str | None  # poe-out: auto-on / forced-on / off
    status: str | None  # poe-out-status, e.g. powered-on, waiting-for-load
    voltage: float | None = None  # V
    current_ma: float | None = None
    power_w: float | None = None


@dataclass(frozen=True)
class LogicalInterface:
    name: str
    kind: str
    parent: str | None = None
    vlan_id: int | None = None
    members: tuple[str, ...] | None = None


@dataclass(frozen=True)
class BridgeMember:
    interface: str
    bridge: str
    pvid: int | None
    hardware_offload_requested: bool | None
    hardware_offload_active: bool | None
    enabled: bool | None = None


@dataclass(frozen=True)
class BridgeConfig:
    name: str
    vlan_filtering: bool | None
    pvid: int | None
    ageing_time_seconds: int | None


@dataclass(frozen=True)
class BridgeVLAN:
    bridge: str
    ranges: tuple[tuple[int, int], ...]
    tagged: tuple[str, ...] | None
    untagged: tuple[str, ...] | None
    current_tagged: tuple[str, ...] | None
    current_untagged: tuple[str, ...] | None
    dynamic: bool | None


@dataclass(frozen=True)
class WiredClient:
    mac: str
    bridge: str
    interface: str | None
    vlan: int | None
    port_idx: int | None
    attachment: str
    dynamic: bool | None
    external: bool | None
    ip: str | None = None
    hostname: str | None = None
    ip_sources: tuple[str, ...] = ()
    ip_candidates: tuple[str, ...] = ()
    observed_uptime_seconds: int = 0
    conflicting_interfaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClientInventory:
    clients: tuple[WiredClient, ...] | None
    sources: dict[str, str]
    fdb_rows: int = 0
    excluded_local: int = 0
    skipped_rows: int = 0


@dataclass(frozen=True)
class NeighborObservation:
    interfaces: tuple[str, ...]
    protocols: tuple[str, ...]
    mac: str | None
    identity: str | None
    remote_port: str | None
    system_description: str | None
    age_seconds: int | None
    port_idx: int | None
    export_reason: str
    evidence: str = "routeros-neighbor-cache"
    certainty: str = "reported"


@dataclass(frozen=True)
class NeighborInventory:
    observations: tuple[NeighborObservation, ...] | None
    source: str = "/ip/neighbor/print"
    excluded_local: int = 0
    invalid_rows: int = 0


@dataclass(frozen=True)
class WANObservation:
    interface: str
    interface_kind: str | None
    enabled: bool
    up: bool
    rx_bytes: int
    tx_bytes: int
    speed_mbps: int | None = None
    full_duplex: bool | None = None
    ip: str | None = None
    netmask: str | None = None
    ipv4_candidates: tuple[str, ...] = ()
    address_status: str = "unavailable"
    evidence: str = "/interface/print"


@dataclass(frozen=True)
class DeviceSnapshot:
    health: DeviceHealth
    ports: tuple[PhysicalPort, ...]
    logical_interfaces: tuple[LogicalInterface, ...] = ()
    bridge_members: tuple[BridgeMember, ...] | None = None
    warnings: tuple[str, ...] = ()
    bridges: tuple[BridgeConfig, ...] | None = None
    bridge_vlans: tuple[BridgeVLAN, ...] | None = None
    wired: ClientInventory | None = None
    neighbors: NeighborInventory | None = None
    wan: WANObservation | None = None
    wan2: WANObservation | None = None
    # Next hop seen in ARP on the uplink port (e.g. the ISP gateway), opt-in.
    uplink_neighbor_mac: str | None = None

    def public(self) -> dict:
        return asdict(self)


def poe_fields(poe: PortPoE) -> dict:
    """PoE port fields as a UniFi PoE switch reports them (values as 2-decimal strings)."""
    delivering = poe.status == "powered-on"

    def reading(value: float | None) -> str:
        return f"{value:.2f}" if delivering and value is not None else "0.00"

    return {
        "port_poe": True,
        "poe_caps": 3,
        "poe_mode": "off" if poe.mode == "off" else "auto",
        "poe_enable": delivering,
        "poe_good": delivering,
        "poe_class": "Unknown",  # RouterOS does not report the PD class here
        "poe_power": reading(poe.power_w),
        "poe_voltage": reading(poe.voltage),
        "poe_current": reading(poe.current_ma),
    }


def lag_fields(snapshot: DeviceSnapshot) -> dict[int, dict]:
    """Port fields a UniFi switch reports for a LAG, from RouterOS bond membership.

    Display only: the lowest mapped member leads the LAG, like a real switch reports it.
    """
    slots = {p.name: p for p in snapshot.ports}
    result: dict[int, dict] = {}
    bonds = [i for i in snapshot.logical_interfaces if i.kind == "bonding" and i.members]
    for lag_idx, bond in enumerate(sorted(bonds, key=lambda b: b.name), 1):
        members = sorted((slots[m] for m in bond.members if m in slots), key=lambda p: p.port_idx)
        if len(members) < 2:
            continue
        lead = members[0].port_idx
        result[lead] = {
            "op_mode": "aggregate",
            "aggregate_num_ports": len(members),
            "aggregate_members": [p.port_idx for p in members],
            "lacp_state": [
                {"active": p.up, "member_port": p.port_idx, "speed": p.speed_mbps or 0}
                for p in members
            ],
            "lag_member": True,
            "lag_idx": lag_idx,
            "aggregated_by": False,
        }
        for p in members[1:]:
            result[p.port_idx] = {"lag_member": True, "aggregated_by": lead, "lag_idx": lag_idx}
    return result


def unifi_snapshot(
    snapshot: DeviceSnapshot,
    *,
    age_seconds: int = 0,
    port_count: int = 8,
    neighbor_macs: bool = False,
    uplink_lldp: bool = False,
    report_lag: bool = False,
) -> dict:
    by_slot = {port.port_idx: port for port in snapshot.ports}
    lags = lag_fields(snapshot) if report_lag else {}
    clients_by_port: dict[int, list] = {i: [] for i in range(1, port_count + 1)}
    clients = snapshot.wired.clients if snapshot.wired is not None else None
    for client in clients or ():
        port = by_slot.get(client.port_idx)
        if client.attachment != "physical" or port is None or not port.enabled or not port.up:
            continue
        entry = {
            "mac": client.mac,
            "age": max(0, age_seconds),
            "uptime": client.observed_uptime_seconds + max(0, age_seconds),
            "static": False,  # Only dynamic or externally learned FDB clients are emitted.
        }
        if client.vlan is not None:
            entry["vlan"] = client.vlan
        if client.ip is not None:
            entry["ip"] = client.ip
        if client.hostname is not None:
            entry["hostname"] = client.hostname
        clients_by_port[client.port_idx].append(entry)
    if neighbor_macs and clients is not None and snapshot.neighbors is not None:
        # An exported neighbor is directly attached to its local port even when the FDB
        # cannot show it (routed port, or learned on a bond): list it there so the
        # controller can build the downlink. Bond members report it on the lowest port.
        # Never on the uplink port: the neighbor there is the parent, not a downlink.
        seen = {e["mac"] for entries in clients_by_port.values() for e in entries}
        for n in sorted(snapshot.neighbors.observations or (), key=lambda n: n.port_idx or 0):
            port = by_slot.get(n.port_idx)
            if (
                n.export_reason != "eligible"
                or n.mac is None
                or n.mac in seen
                or port is None
                or port.is_uplink
                or not port.enabled
                or not port.up
            ):
                continue
            seen.add(n.mac)
            clients_by_port[n.port_idx].append(
                {"mac": n.mac, "age": max(0, age_seconds), "uptime": 0, "static": False}
            )
    upstream = snapshot.uplink_neighbor_mac
    if upstream and clients is not None:
        uplink = next((p for p in snapshot.ports if p.is_uplink and p.enabled and p.up), None)
        listed = {e["mac"] for entries in clients_by_port.values() for e in entries}
        if uplink is not None and upstream not in listed:
            # The parent on the uplink port: lets the controller see this device's upstream.
            clients_by_port[uplink.port_idx].append(
                {"mac": upstream, "age": max(0, age_seconds), "uptime": 0, "static": False}
            )
    ports = []
    for slot in range(1, port_count + 1):
        port = by_slot.get(slot)
        if port is None:
            entry = {"port_idx": slot, "enable": False, "up": False, "speed": 0}
            if clients is not None:
                entry["mac_table"] = []
            ports.append(entry)
            continue
        entry = {
            "port_idx": slot,
            "name": port.name,
            "enable": port.enabled,
            "up": port.up,
            "is_uplink": port.is_uplink,
            "rx_bytes": port.rx_bytes,
            "tx_bytes": port.tx_bytes,
        }
        # Unknown live speed/duplex is omitted, never replaced with a guessed gigabit link.
        if not port.up:
            entry.update(speed=0, full_duplex=False)
        else:
            if port.speed_mbps is not None:
                entry["speed"] = port.speed_mbps
            if port.full_duplex is not None:
                entry["full_duplex"] = port.full_duplex
        if port.autoneg is not None:
            entry["autoneg"] = port.autoneg
        if clients is not None:
            entry["mac_table"] = clients_by_port[slot]
        entry |= lags.get(slot, {})
        if port.poe is not None:
            entry |= poe_fields(port.poe)
        ports.append(entry)
    health = snapshot.health
    stats = {}
    if health.cpu_percent is not None:
        stats["cpu"] = str(health.cpu_percent)
    if health.memory_total_bytes and health.memory_free_bytes is not None:
        stats["mem"] = f"{100 * (1 - health.memory_free_bytes / health.memory_total_bytes):.1f}"
    body = {"port_table": ports, "uptime": health.uptime_seconds}
    if stats:
        body["system-stats"] = stats
    neighbors = (
        snapshot.neighbors.observations
        if snapshot.neighbors is not None and snapshot.neighbors.invalid_rows == 0
        else None
    )
    if neighbors is not None:
        body["lldp_table"] = []
        emitted = set()
        for neighbor in neighbors:
            if neighbor.export_reason != "eligible":
                continue
            port = by_slot.get(neighbor.port_idx)
            identity = (neighbor.port_idx, neighbor.mac, neighbor.remote_port)
            if port is None or not port.enabled or not port.up or identity in emitted:
                continue
            emitted.add(identity)
            entry = {
                "chassis_id": neighbor.mac,
                "local_port_idx": port.port_idx,
                "local_port_name": port.name,
                "port_id": neighbor.remote_port,
                "is_wired": True,
            }
            if neighbor.system_description or neighbor.identity:
                entry["chassis_descr"] = neighbor.system_description or neighbor.identity
            body["lldp_table"].append(entry)
    upstream = snapshot.uplink_neighbor_mac
    uplink = next((p for p in snapshot.ports if p.is_uplink and p.enabled and p.up), None)
    if uplink_lldp and upstream and uplink is not None and "lldp_table" in body:
        # Derived from ARP, not a received LLDP frame: the ISP gateway sends no LLDP. It
        # gives the controller an upstream on this device's own uplink port (opt-in).
        body["lldp_table"].append(
            {
                "chassis_id": upstream,
                "local_port_idx": uplink.port_idx,
                "local_port_name": uplink.name,
                "port_id": "wan",
                "chassis_descr": "ISP gateway (derived from ARP)",
                "is_wired": True,
            }
        )
    return body
