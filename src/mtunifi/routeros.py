"""Read-only RouterOS collector with explicit physical-port mapping and reconnects."""

import asyncio
import re
import time
from dataclasses import replace
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from mtunifi.clients import ClientTracker, correlate_clients, mac_address
from mtunifi.config import Settings
from mtunifi.gateway import collect_gateway, gateway_snapshot
from mtunifi.neighbors import collect_neighbors
from mtunifi.profiles import profile
from mtunifi.routeros_api import RouterOSAPI, RouterOSError, Table, api_error, api_target
from mtunifi.routeros_values import (
    boolean,
    indexed,
    link_speed,
    number,
    resource_health,
    text,
)
from mtunifi.routeros_values import (
    check_version as check_version,
)
from mtunifi.routeros_values import (
    uptime_seconds as uptime_seconds,
)
from mtunifi.scenario import LabModel
from mtunifi.snapshot import (
    BridgeMember,
    DeviceSnapshot,
    LogicalInterface,
    PhysicalPort,
    PortPoE,
    unifi_snapshot,
)

# Interface types that may fill a slot without an ethernet monitor (link speed unknown).
UNMONITORED_TYPES = ("ether", "wlan", "wifi")
BOND_TYPES = ("bond", "bonding")


class PortMapping(LabModel):
    port_idx: int = Field(ge=1, le=26)
    interface: str = Field(min_length=1, max_length=128)
    is_uplink: bool = False
    # Declared by the operator for interfaces without a link monitor (e.g. wlan);
    # reported while the interface is up, flagged in warnings, never measured.
    assumed_speed_mbps: int | None = Field(default=None, ge=1, le=100000)
    # Gateway interface name the controller expects for this slot (e.g. eth8 on a UGWXG).
    ifname: str | None = Field(default=None, pattern=r"^eth\d{1,2}$")

    @field_validator("interface")
    @classmethod
    def printable_name(cls, value):
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Control characters are not allowed")
        return value


class RouterOSMap(LabModel):
    schema_version: Literal[1] = 1
    profile: str = "us8-experimental"
    ports: list[PortMapping] = Field(min_length=1, max_length=26)

    @model_validator(mode="after")
    def unique_ports(self):
        if any(p.port_idx > profile(self.profile).port_count for p in self.ports):
            raise ValueError("Port slot exceeds the selected profile")
        if len({p.port_idx for p in self.ports}) != len(self.ports) or len(
            {p.interface for p in self.ports}
        ) != len(self.ports):
            raise ValueError("Each slot and interface must have one mapping")
        ifnames = [p.ifname for p in self.ports if p.ifname is not None]
        if len(set(ifnames)) != len(ifnames):
            raise ValueError("Each gateway ifname must have one mapping")
        return self


def load_mapping(path: Path) -> RouterOSMap:
    try:
        with path.open("rb") as handle:
            raw = handle.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise ValueError
        return RouterOSMap.model_validate_json(raw)
    except (OSError, ValueError, ValidationError):
        raise RouterOSError("port-map-invalid") from None


async def collect_device(
    api: RouterOSAPI,
    mapping: RouterOSMap,
    device_mac: str = "",
    *,
    relaxed_neighbors: bool = False,
    neighbor_mac_aliases: dict[str, str] | None = None,
    uplink_from_arp: bool = False,
    read_poe: bool = False,
) -> DeviceSnapshot:
    resources = await api.table(Table.RESOURCE)
    if len(resources) != 1:
        raise RouterOSError("invalid-resource-table")
    resource = resources[0]
    health, warnings = resource_health(resource)
    interfaces = indexed(await api.table(Table.INTERFACES))
    ethernet = indexed(await api.table(Table.ETHERNET))

    async def optional(table):
        try:
            return await api.table(table)
        except RouterOSError as exc:
            # Permission/unsupported table are recoverable; a broken stream is not reusable.
            if exc.code not in ("permission-denied", "endpoint-unavailable", "request-rejected"):
                raise
            warnings.append(table.name.lower() + ":" + exc.code)
            return None

    identity = await optional(Table.IDENTITY)
    health = replace(
        health, identity=text(identity[0].get("name")) if identity and len(identity) == 1 else None
    )
    ports = []
    for item in sorted(mapping.ports, key=lambda p: p.port_idx):
        eth, stats = ethernet.get(item.interface), interfaces.get(item.interface)
        unmonitored = eth is None and stats is not None and stats.get("type") in UNMONITORED_TYPES
        if (
            stats is None
            or (eth is None and not unmonitored)
            or (eth is not None and stats.get("type") != "ether")
        ):
            raise RouterOSError("mapped-physical-interface-missing")
        eth = eth or {}
        disabled, running = boolean(stats.get("disabled")), boolean(stats.get("running"))
        rx, tx = number(stats.get("rx-byte")), number(stats.get("tx-byte"))
        if disabled is None or running is None or rx is None or tx is None:
            raise RouterOSError("required-interface-data-missing")
        monitor = None
        if not unmonitored:
            try:
                records = await api.monitor(eth.get(".id", item.interface))
                if len(records) == 1:
                    monitor = records[0]
            except RouterOSError as exc:
                if exc.code not in (
                    "permission-denied",
                    "endpoint-unavailable",
                    "request-rejected",
                ):
                    raise
            if monitor is None:
                warnings.append(f"port-{item.port_idx}:monitor-unavailable")
        monitor = monitor or {}
        up = not disabled and running
        if monitor.get("status") in ("no-link", "link-ok"):
            up = not disabled and monitor["status"] == "link-ok"
        speed = link_speed(monitor.get("rate")) if up else None
        duplex = boolean(monitor.get("full-duplex")) if up else None
        if up and unmonitored and item.assumed_speed_mbps is not None:
            speed, duplex = item.assumed_speed_mbps, True
            warnings.append(f"port-{item.port_idx}:assumed-speed")
        if up and not unmonitored and (speed is None or duplex is None):
            warnings.append(f"port-{item.port_idx}:link-details-unavailable")
        if speed is not None and speed > profile(mapping.profile).max_speeds[item.port_idx - 1]:
            warnings.append(f"port-{item.port_idx}:exceeds-profile-capacity")
        ports.append(
            PhysicalPort(
                port_idx=item.port_idx,
                name=item.interface,
                default_name=text(eth.get("default-name")),
                mac=text(eth.get("mac-address") or stats.get("mac-address"), 17),
                enabled=not disabled,
                up=up,
                speed_mbps=speed,
                full_duplex=duplex,
                autoneg={"done": True, "failed": True, "disabled": False}.get(
                    monitor.get("auto-negotiation")
                ),
                rx_bytes=rx,
                tx_bytes=tx,
                is_uplink=item.is_uplink,
            )
        )
    if read_poe:
        ports = await with_poe(api, ports, warnings)
    # Logical interfaces are inventory/context only; never count them as physical ports.
    vlans = (
        await optional(Table.VLANS)
        if any(i.get("type") == "vlan" for i in interfaces.values())
        else []
    )
    bonds = (
        await optional(Table.BONDS)
        if any(i.get("type") in BOND_TYPES for i in interfaces.values())
        else []
    )
    vlan_by_name = {r.get("name"): r for r in vlans or []}
    bond_by_name = {r.get("name"): r for r in bonds or []}
    logical = []
    for name, row in interfaces.items():
        # RouterOS 7 reports bonding interfaces with type "bond".
        kind = "bonding" if row.get("type") in BOND_TYPES else row.get("type")
        if kind not in ("bridge", "vlan", "bonding"):
            continue
        vlan, bond = vlan_by_name.get(name, {}), bond_by_name.get(name, {})
        slaves = text(bond.get("slaves"), 1024)
        logical.append(
            LogicalInterface(
                name=name,
                kind=kind,
                parent=text(vlan.get("interface")),
                vlan_id=number(vlan.get("vlan-id"), 4094),
                members=tuple(slaves.split(",")) if slaves else None,
            )
        )
    members = None
    if any(i.kind == "bridge" for i in logical):
        records = await optional(Table.BRIDGE_PORTS)
        if records is not None:
            members = []
            for row in records:
                interface, bridge = text(row.get("interface")), text(row.get("bridge"))
                if interface and bridge:
                    members.append(
                        BridgeMember(
                            interface=interface,
                            bridge=bridge,
                            pvid=number(row.get("pvid"), 4094),
                            hardware_offload_requested=boolean(row.get("hw")),
                            hardware_offload_active=boolean(row.get("hw-offload")),
                            enabled=(not boolean(row["disabled"]))
                            if boolean(row.get("disabled")) is not None
                            else None,
                        )
                    )
                else:
                    warnings.append("bridge_ports:invalid-row")
    snapshot = DeviceSnapshot(
        health,
        tuple(ports),
        tuple(logical),
        tuple(members) if members is not None else None,
        tuple(sorted(set(warnings))),
    )
    bridge_rows = await optional(Table.BRIDGES) if any(i.kind == "bridge" for i in logical) else []
    vlan_rows = await optional(Table.BRIDGE_VLANS) if bridge_rows != [] else []
    hosts = await optional(Table.BRIDGE_HOSTS)
    arp = await optional(Table.ARP)
    leases = await optional(Table.DHCP_LEASES)
    servers = await optional(Table.DHCP_SERVERS) if leases else None
    neighbors = await optional(Table.NEIGHBORS)
    snapshot = replace(snapshot, warnings=tuple(sorted(set(warnings))))
    snapshot = correlate_clients(
        snapshot,
        interfaces=interfaces,
        bridge_rows=bridge_rows,
        vlan_rows=vlan_rows,
        hosts=hosts,
        arp=arp,
        leases=leases,
        servers=servers,
        device_mac=device_mac,
        extra_local_macs=tuple(row.get("mac-address") for row in ethernet.values()),
    )
    local_macs = (
        device_mac,
        *(r.get("mac-address") for r in interfaces.values()),
        *(r.get("mac-address") for r in ethernet.values()),
        *(r.get(k) for r in bridge_rows or () for k in ("mac-address", "admin-mac")),
    )
    snapshot = collect_neighbors(
        snapshot,
        neighbors,
        local_macs=local_macs,
        relaxed=relaxed_neighbors,
        mac_aliases=neighbor_mac_aliases,
    )
    if uplink_from_arp:
        snapshot = uplink_neighbor(snapshot, mapping, arp, local_macs)
    return snapshot


def poe_number(value: str | None) -> float | None:
    """RouterOS PoE readings such as "24.4", "24.4V", "93mA" or "2.2W"."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(?:V|mA|W)?\s*", value or "")
    return float(match[1]) if match else None


async def with_poe(api: RouterOSAPI, ports: list, warnings: list) -> list:
    """Attach observed PoE-out state to RJ45 ports; unsupported/forbidden reads only warn."""
    names = tuple(p.name for p in ports if p.name.startswith("ether"))
    if not names:
        return ports
    try:
        rows = await api.poe_monitor(names)
    except RouterOSError as exc:
        if exc.code not in ("permission-denied", "endpoint-unavailable", "request-rejected"):
            raise
        warnings.append("poe:" + exc.code)
        return ports
    by_name = {r.get("name"): r for r in rows}
    result = []
    for port in ports:
        row = by_name.get(port.name)
        if row is None:
            result.append(port)
            continue
        poe = PortPoE(
            mode=text(row.get("poe-out")),
            status=text(row.get("poe-out-status")),
            voltage=poe_number(row.get("poe-out-voltage")),
            current_ma=poe_number(row.get("poe-out-current")),
            power_w=poe_number(row.get("poe-out-power")),
        )
        result.append(replace(port, poe=poe))
    return result


def uplink_neighbor(
    snapshot: DeviceSnapshot, mapping: RouterOSMap, arp: list[dict] | None, local_macs
) -> DeviceSnapshot:
    """The single resolved ARP neighbor on the uplink port (e.g. the ISP gateway)."""
    names = {p.interface for p in mapping.ports if p.is_uplink}
    local = {mac_address(m) for m in local_macs} - {None}
    candidates = (
        {
            mac_address(r.get("mac-address"))
            for r in arp or ()
            if r.get("interface") in names
            and boolean(r.get("invalid")) is not True
            and boolean(r.get("disabled")) is not True
            and r.get("status") not in ("failed", "incomplete")
        }
        - local
        - {None}
    )
    if len(candidates) == 1:
        return replace(snapshot, uplink_neighbor_mac=next(iter(candidates)))
    reason = "uplink-arp:none" if not candidates else "uplink-arp:ambiguous"
    return replace(snapshot, warnings=tuple(sorted({*snapshot.warnings, reason})))


def poe_totals(snapshot: DeviceSnapshot, budget_w: float) -> dict:
    """Device-level PoE budget/usage as a UniFi PoE switch reports it."""
    used = sum(
        p.poe.power_w or 0.0
        for p in snapshot.ports
        if p.poe is not None and p.poe.status == "powered-on"
    )
    return {
        "total_max_power": budget_w,
        "total_max_effective_power": budget_w,
        "total_used_power": round(used, 2),
    }


def management_interface(body: dict, device_mac: str, device_ip: str) -> dict:
    """Uplink name and eth0 interface, mirroring the uplink port's observed link state."""
    uplink = next((p for p in body["port_table"] if p.get("is_uplink")), None)
    entry = {"name": "eth0", "ip": device_ip, "up": bool(uplink and uplink.get("up"))}
    if device_mac:
        entry["mac"] = device_mac
    if uplink is not None:
        for key in ("speed", "full_duplex", "rx_bytes", "tx_bytes"):
            if key in uplink:
                entry[key] = uplink[key]
    return {"uplink": "eth0", "if_table": [entry]}


class RouterOSSource:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.gateway = profile(settings.profile).kind == "gateway"
        self.mapping = None
        if settings.routeros_map_file is not None:
            self.mapping = load_mapping(settings.routeros_map_file)
            if self.mapping.profile != settings.profile:
                if not self.gateway:
                    raise RouterOSError("port-map-profile-mismatch")
                # Gateways historically ignored a port map: only a map written for this very
                # profile makes the gateway report its ports next to the WAN.
                self.mapping = None
        self._neighbor_options = {
            "relaxed_neighbors": settings.routeros_neighbors_relaxed,
            "neighbor_mac_aliases": settings.neighbor_mac_aliases,
            "uplink_from_arp": settings.routeros_uplink_from_arp,
            "read_poe": settings.routeros_poe,
        }
        self.status = "unavailable"
        self.last_summary = None
        self._snapshot: DeviceSnapshot | None = None
        self._next_poll = 0.0
        self._observed_at: float | None = None
        self._failures = 0
        self._error: RouterOSError | None = None
        self._clients = ClientTracker()
        self._observed_mono = 0.0

    async def collect(self, now: float, device_mac: str) -> dict:
        if now >= self._next_poll:
            api = RouterOSAPI(self.settings)
            try:
                async with asyncio.timeout(self.settings.routeros_timeout):
                    # One bounded session per poll: failures reconnect without sharing credentials
                    # or a socket with another device. Secret rotations apply on the next poll.
                    async with api:
                        if self.gateway:
                            snapshot = await collect_gateway(api, self.settings)
                            if self.mapping is not None:
                                ports = await collect_device(
                                    api, self.mapping, device_mac, **self._neighbor_options
                                )
                                snapshot = replace(
                                    ports,
                                    wan=snapshot.wan,
                                    wan2=snapshot.wan2,
                                    warnings=tuple(sorted({*snapshot.warnings, *ports.warnings})),
                                )
                        else:
                            snapshot = await collect_device(
                                api, self.mapping, device_mac, **self._neighbor_options
                            )
                previous = self._snapshot
                reset = previous is not None and (
                    snapshot.health.uptime_seconds < previous.health.uptime_seconds
                    or any(
                        p.rx_bytes < old.rx_bytes or p.tx_bytes < old.tx_bytes
                        for p, old in zip(snapshot.ports, previous.ports, strict=True)
                    )
                    or (
                        snapshot.wan is not None
                        and previous.wan is not None
                        and (
                            snapshot.wan.rx_bytes < previous.wan.rx_bytes
                            or snapshot.wan.tx_bytes < previous.wan.tx_bytes
                        )
                    )
                )
                if reset:
                    snapshot = replace(snapshot, warnings=(*snapshot.warnings, "counters:reset"))
                    self._clients.clear()
                snapshot = self._clients.observe(snapshot, now)
                self._snapshot = snapshot
                self._observed_at = time.time()
                self._observed_mono = now
                self.status = "degraded" if snapshot.warnings else "active"
                self._error, self._failures = None, 0
                self._next_poll = now + self.settings.routeros_poll_interval
            except (RouterOSError, OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
                self._error = api_error(exc, api.stage)
                self._failures = min(5, self._failures + 1)
                self._next_poll = now + min(
                    60, self.settings.routeros_poll_interval * 2 ** (self._failures - 1)
                )
                self.status = "unavailable"
                self._clients.clear()
        snapshot = self._snapshot
        body = None
        if snapshot is not None and self._error is None:
            ports = (
                unifi_snapshot(
                    snapshot,
                    age_seconds=max(0, int(now - self._observed_mono)),
                    port_count=profile(self.settings.profile).port_count,
                    neighbor_macs=self.settings.routeros_neighbors_relaxed,
                    uplink_lldp=self.settings.routeros_uplink_lldp_from_arp,
                    report_lag=self.settings.report_lag,
                )
                if self.mapping is not None
                else None
            )
            if self.gateway:
                ifnames = (
                    {p.interface: p.ifname for p in self.mapping.ports}
                    if self.mapping is not None and all(p.ifname for p in self.mapping.ports)
                    else None
                )
                body = gateway_snapshot(snapshot, device_mac, ifnames)
                if ports is not None and ifnames is None:
                    body |= {k: ports[k] for k in ("port_table", "lldp_table") if k in ports}
            else:
                body = ports
                if self.settings.report_uplink:
                    body |= management_interface(body, device_mac, self.settings.device_ip)
                if self.settings.poe_budget_w and any(p.poe for p in snapshot.ports):
                    body |= poe_totals(snapshot, self.settings.poe_budget_w)
        identity = snapshot.health.identity if snapshot is not None else None
        if (
            body is not None
            and self.settings.hostname_from_identity
            and identity is not None
            and re.fullmatch(r"[A-Za-z0-9-]{1,63}", identity)
        ):
            body["hostname"] = identity
        clients = snapshot.wired.clients if snapshot and snapshot.wired else None
        self.last_summary = {
            "source": "routeros",
            "target": api_target(self.settings),
            "status": self.status,
            "observed_at": self._observed_at,
            "age_seconds": max(0, time.time() - self._observed_at)
            if self._observed_at is not None
            else None,
            "active_clients": (
                sum(len(p.get("mac_table", [])) for p in body["port_table"])
                if "port_table" in body
                # USG-style gateways have no per-port MAC tables; count attached clients.
                else sum(c.attachment == "physical" for c in clients)
            )
            if body is not None and clients is not None
            else None,
            "clients_status": "unavailable" if clients is None or body is None else "observed",
            "unresolved_clients": sum(c.attachment != "physical" for c in clients)
            if clients is not None and body is not None
            else None,
            "neighbors": len(body["lldp_table"])
            if body is not None and "lldp_table" in body
            else None,
            "neighbors_status": "observed"
            if body is not None and "lldp_table" in body
            else "unavailable",
            "neighbor_observations": len(snapshot.neighbors.observations)
            if body is not None
            and snapshot.neighbors
            and snapshot.neighbors.observations is not None
            else None,
            "mapped_physical_ports": len(self.mapping.ports) if self.mapping else 0,
            "wan_interface": self.settings.routeros_wan_interface if self.gateway else None,
            "source_error": self._error.code if self._error else None,
            "source_error_details": self._error.public() if self._error else None,
            "observations": snapshot.public() if snapshot else None,
        }
        if self._error is not None:
            # Retain the previous snapshot only for diagnosis, never send stale observations
            # as fresh telemetry or silently fall back to synthetic ports/clients.
            raise self._error
        return body
