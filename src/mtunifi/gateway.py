"""Read-only WAN observations and the explicit UGW3 inform adapter."""

import ipaddress
from dataclasses import replace

from mtunifi.clients import ipv4
from mtunifi.config import Settings
from mtunifi.routeros_api import RouterOSAPI, RouterOSError, Table
from mtunifi.routeros_values import boolean, indexed, link_speed, number, resource_health, text
from mtunifi.snapshot import DeviceSnapshot, WANObservation


def wan_addresses(rows: list[dict] | None, interface: str) -> tuple[tuple[str, ...], str]:
    if rows is None:
        return (), "unavailable"
    addresses = set()
    malformed = False
    for row in rows:
        if (row.get("actual-interface") or row.get("interface")) != interface:
            continue
        if boolean(row.get("disabled")) is True or boolean(row.get("invalid")) is True:
            continue
        if any(key in row and boolean(row[key]) is None for key in ("disabled", "invalid")):
            malformed = True
            continue
        try:
            raw = text(row.get("address"), 64)
            if raw is None or "/" not in raw:
                raise ValueError
            address = ipaddress.IPv4Interface(raw)
            if ipv4(str(address.ip)) is None:
                raise ValueError
        except (ValueError, TypeError):
            malformed = True
            continue
        addresses.add(str(address))
    if malformed:
        return tuple(sorted(addresses))[:8], "invalid"
    return tuple(sorted(addresses))[:8], "ambiguous" if len(addresses) > 1 else "observed"


async def collect_gateway(api: RouterOSAPI, settings: Settings) -> DeviceSnapshot:
    resources = await api.table(Table.RESOURCE)
    if len(resources) != 1:
        raise RouterOSError("invalid-resource-table")
    health, warnings = resource_health(resources[0])

    async def optional(table):
        try:
            return await api.table(table)
        except RouterOSError as exc:
            if exc.code not in ("permission-denied", "endpoint-unavailable", "request-rejected"):
                raise
            warnings.append(table.name.lower() + ":" + exc.code)
            return None

    interfaces = indexed(await api.table(Table.INTERFACES))
    ethernet_table = None
    ip_rows = None
    ip_loaded = False

    async def observe(name: str, label: str) -> WANObservation:
        nonlocal ethernet_table, ip_rows, ip_loaded
        row = interfaces.get(name)
        if row is None:
            raise RouterOSError("wan-interface-missing", stage=Table.INTERFACES.value)
        disabled, running = boolean(row.get("disabled")), boolean(row.get("running"))
        rx, tx = number(row.get("rx-byte")), number(row.get("tx-byte"))
        if disabled is None or running is None or rx is None or tx is None:
            raise RouterOSError("required-wan-data-missing", stage=Table.INTERFACES.value)
        up = not disabled and running
        speed, duplex = None, None
        kind = text(row.get("type"))
        if kind == "ether":
            if ethernet_table is None:
                ethernet_table = await optional(Table.ETHERNET) or []
            matches = [r for r in ethernet_table if r.get("name") == name]
            monitor = None
            if len(matches) == 1:
                try:
                    records = await api.monitor(matches[0].get(".id", name))
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
                warnings.append(f"{label}:monitor-unavailable")
            else:
                if monitor.get("status") in ("link-ok", "no-link"):
                    up = not disabled and monitor["status"] == "link-ok"
                if up:
                    speed = link_speed(monitor.get("rate"))
                    duplex = boolean(monitor.get("full-duplex"))
                    if speed is None or duplex is None:
                        warnings.append(f"{label}:link-details-unavailable")
        if not ip_loaded:
            ip_rows = await optional(Table.IP_ADDRESSES)
            ip_loaded = True
        addresses, address_status = wan_addresses(ip_rows, name)
        ip, netmask = None, None
        if address_status == "observed" and len(addresses) == 1:
            selected = ipaddress.IPv4Interface(addresses[0])
            ip, netmask = str(selected.ip), str(selected.netmask)
        if address_status != "observed":
            warnings.append(f"{label}:ipv4-{address_status}")
        return WANObservation(
            name,
            kind,
            not disabled,
            up,
            rx,
            tx,
            speed,
            duplex,
            ip,
            netmask,
            addresses,
            address_status,
        )

    wan = await observe(settings.routeros_wan_interface, "wan")
    wan2 = (
        await observe(settings.routeros_wan2_interface, "wan2")
        if settings.routeros_wan2_interface
        else None
    )
    identity = await optional(Table.IDENTITY)
    health = replace(
        health, identity=text(identity[0].get("name")) if identity and len(identity) == 1 else None
    )
    return DeviceSnapshot(
        health,
        (),
        warnings=tuple(sorted(set(warnings))),
        wan=wan,
        wan2=wan2,
    )


def _if_entry(wan: WANObservation, ifname: str, mac: str) -> dict:
    entry = {
        "name": ifname,
        "enable": wan.enabled,
        "up": wan.up,
        "rx_bytes": wan.rx_bytes,
        "tx_bytes": wan.tx_bytes,
    }
    # The interface belongs to the synthetic gateway, never borrow a physical device MAC.
    if mac:
        entry["mac"] = mac
    if not wan.up:
        entry["speed"] = 0
    elif wan.speed_mbps is not None:
        entry["speed"] = wan.speed_mbps
    if wan.full_duplex is not None and wan.up:
        entry["full_duplex"] = wan.full_duplex
    if wan.ip is not None:
        entry.update(ip=wan.ip, netmask=wan.netmask)
    return entry


def _next_mac(mac: str, offset: int = 1) -> str:
    if not mac:
        return ""
    head, _, last = mac.rpartition(":")
    return f"{head}:{(int(last, 16) + offset) % 256:02x}"


def _mapped_interfaces(
    snapshot: DeviceSnapshot, device_mac: str, ifnames: dict[str, str]
) -> tuple[list[dict], list[dict], str]:
    """Every mapped port becomes one gateway interface; WAN roles follow the WAN settings."""
    wans = {snapshot.wan.interface: (snapshot.wan, "wan")}
    if snapshot.wan2 is not None:
        wans[snapshot.wan2.interface] = (snapshot.wan2, "wan2")
    if any(name not in ifnames for name in wans):
        raise RouterOSError("wan-interface-unmapped")
    interfaces, config, lan = [], [], 0
    for port in sorted(snapshot.ports, key=lambda p: int(ifnames[p.name][3:])):
        ifname = ifnames[port.name]
        entry = {
            "name": ifname,
            "enable": port.enabled,
            "up": port.up,
            "rx_bytes": port.rx_bytes,
            "tx_bytes": port.tx_bytes,
        }
        mac = _next_mac(device_mac, int(ifname[3:]))
        if mac:
            entry["mac"] = mac
        if not port.up:
            entry["speed"] = 0
        elif port.speed_mbps is not None:
            entry["speed"] = port.speed_mbps
        if port.full_duplex is not None and port.up:
            entry["full_duplex"] = port.full_duplex
        if port.name in wans:
            observation, role = wans[port.name]
            if observation.ip is not None:
                entry.update(ip=observation.ip, netmask=observation.netmask)
            config.append({"ifname": ifname, "name": role, "type": "wan"})
        else:
            lan += 1
            name = "lan" if lan == 1 else f"lan{lan}"
            config.append({"ifname": ifname, "name": name, "type": "lan"})
        interfaces.append(entry)
    return interfaces, config, ifnames[snapshot.wan.interface]


def gateway_snapshot(
    snapshot: DeviceSnapshot, device_mac: str, ifnames: dict[str, str] | None = None
) -> dict:
    wan = snapshot.wan
    if wan is None:
        raise RouterOSError("required-wan-data-missing")
    if ifnames:
        interfaces, config, uplink = _mapped_interfaces(snapshot, device_mac, ifnames)
        return _with_stats(
            snapshot,
            {
                "uptime": snapshot.health.uptime_seconds,
                "uplink": uplink,
                "config_port_table": config,
                "if_table": interfaces,
            },
        )
    # UGW3 firmware names WAN eth0; 10.6.106 does not derive wan1 from arbitrary
    # RouterOS names. Keep the source name in WANObservation and export this alias.
    # A second WAN uses eth2, matching the USG-3P WAN2/LAN2 port.
    interfaces = [_if_entry(wan, "eth0", device_mac)]
    config = [{"ifname": "eth0", "name": "wan", "type": "wan"}]
    if snapshot.wan2 is not None:
        interfaces.append(_if_entry(snapshot.wan2, "eth2", _next_mac(device_mac)))
        config.append({"ifname": "eth2", "name": "wan2", "type": "wan"})
    body = {
        "uptime": snapshot.health.uptime_seconds,
        "uplink": "eth0",
        "config_port_table": config,
        "if_table": interfaces,
    }
    return _with_stats(snapshot, body)


def _with_stats(snapshot: DeviceSnapshot, body: dict) -> dict:
    stats = {}
    health = snapshot.health
    if health.cpu_percent is not None:
        stats["cpu"] = str(health.cpu_percent)
    if health.memory_total_bytes and health.memory_free_bytes is not None:
        stats["mem"] = f"{100 * (1 - health.memory_free_bytes / health.memory_total_bytes):.1f}"
    if stats:
        body["system-stats"] = stats
    return body
