"""FDB attachment authority with scoped, optional ARP/DHCP enrichment."""

import ipaddress
import re
from collections import defaultdict
from dataclasses import replace

from mtunifi.routeros_api import RouterOSError
from mtunifi.routeros_values import boolean, number, text, uptime_seconds
from mtunifi.snapshot import BridgeConfig, BridgeVLAN, ClientInventory, DeviceSnapshot, WiredClient


def mac_address(value: str | None) -> str | None:
    if value and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        raw = bytes.fromhex(value.replace(":", ""))
        if not raw[0] & 1 and any(raw):
            return value.lower()
    return None


def ipv4(value: str | None) -> str | None:
    try:
        address = ipaddress.IPv4Address(value)
        if not (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
            or int(address) == 2**32 - 1
        ):
            return str(address)
    except (ValueError, TypeError):
        pass
    return None


def vlan_id(value: str | None) -> int | None:
    result = number(value, 4094)
    return result if result is not None and result > 0 else None


def vlan_ranges(value: str | None) -> tuple[tuple[int, int], ...] | None:
    if not value or len(value) > 1024:
        return None
    parts = value.split(",")
    if len(parts) > 64:
        return None
    result = []
    for part in parts:
        match = re.fullmatch(r"([0-9]{1,4})(?:-([0-9]{1,4}))?", part)
        if match is None:
            return None
        start, end = int(match[1]), int(match[2] or match[1])
        if not 1 <= start <= end <= 4094:
            return None
        result.append((start, end))
    return tuple(sorted(set(result)))


def name_list(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if value == "":
        return ()
    parts = value.split(",")
    if len(value) > 4096 or len(parts) > 128 or any(text(p) is None for p in parts):
        return None
    return tuple(sorted(set(parts)))


def _bridges(rows, warnings):
    if rows is None:
        return None
    result = []
    for row in rows:
        name = text(row.get("name"))
        if name is None:
            warnings.add("bridges:invalid-row")
            continue
        try:
            ageing = uptime_seconds(row.get("ageing-time"))
        except RouterOSError:
            ageing = None
        result.append(
            BridgeConfig(name, boolean(row.get("vlan-filtering")), vlan_id(row.get("pvid")), ageing)
        )
    if len({b.name for b in result}) != len(result):
        warnings.add("bridges:ambiguous")
        return None
    return tuple(result)


def _bridge_vlans(rows, warnings):
    if rows is None:
        return None
    result = []
    for row in rows:
        if boolean(row.get("disabled")) is True:
            continue
        bridge, ranges = text(row.get("bridge")), vlan_ranges(row.get("vlan-ids"))
        if bridge is None or ranges is None:
            warnings.add("bridge_vlans:invalid-row")
            continue
        result.append(
            BridgeVLAN(
                bridge,
                ranges,
                name_list(row.get("tagged")),
                name_list(row.get("untagged")),
                name_list(row.get("current-tagged")),
                name_list(row.get("current-untagged")),
                boolean(row.get("dynamic")),
            )
        )
    return tuple(result)


def correlate_clients(
    snapshot: DeviceSnapshot,
    *,
    interfaces: dict,
    bridge_rows: list | None,
    vlan_rows: list | None,
    hosts: list | None,
    arp: list | None,
    leases: list | None,
    servers: list | None,
    device_mac: str = "",
    extra_local_macs: tuple[str | None, ...] = (),
) -> DeviceSnapshot:
    warnings = set(snapshot.warnings)
    bridges = _bridges(bridge_rows, warnings)
    rules = _bridge_vlans(vlan_rows, warnings)
    bridge_by_name = {b.name: b for b in bridges or ()}
    sources = {
        "fdb": "available" if hosts is not None else "unavailable",
        "arp": "available" if arp is not None else "unavailable",
        "dhcp_leases": "available" if leases is not None else "unavailable",
        "dhcp_servers": "available"
        if servers is not None
        else "unavailable"
        if leases
        else "not-needed",
    }
    if hosts is None:
        inventory = ClientInventory(None, sources)
        return replace(
            snapshot,
            bridges=bridges,
            bridge_vlans=rules,
            wired=inventory,
            warnings=tuple(sorted(warnings)),
        )

    local_macs = {m for row in interfaces.values() if (m := mac_address(row.get("mac-address")))}
    local_macs.update(m for value in extra_local_macs if (m := mac_address(value)))
    for row in bridge_rows or ():
        local_macs.update(
            m for field in ("mac-address", "admin-mac") if (m := mac_address(row.get(field)))
        )
    if own := mac_address(device_mac):
        local_macs.add(own)
    ports = {p.name: p for p in snapshot.ports}
    members = defaultdict(list)
    for member in snapshot.bridge_members or ():
        members[member.interface].append(member)
    grouped = defaultdict(list)
    excluded, skipped, invalid = 0, 0, False
    for row in hosts:
        mac = mac_address(row.get("mac-address"))
        if boolean(row.get("local")) is True or mac in local_macs:
            excluded += 1
            continue
        if boolean(row.get("invalid")) is True or boolean(row.get("disabled")) is True:
            skipped += 1
            continue
        if mac is None:
            # Well-formed multicast/zero MACs are non-client entries, not malformed identity.
            raw = row.get("mac-address", "")
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", raw):
                skipped += 1
                continue
            invalid = True
            skipped += 1
            continue
        bridge, interface = text(row.get("bridge")), text(row.get("on-interface"))
        if (
            bridge is None
            or interface is None
            or row.get("vid") not in (None, "", "0")
            and (vlan_id(row.get("vid")) is None)
        ):
            invalid = True
            skipped += 1
            continue
        vid = vlan_id(row.get("vid"))
        if bridge in bridge_by_name and bridge_by_name[bridge].vlan_filtering is False:
            vid = None  # A VLAN-unaware FDB does not distinguish tagged client VLANs.
        grouped[(bridge, mac, vid)].append(row)
    if invalid:
        warnings.add("fdb:invalid-rows")
        sources["fdb"] = "invalid"
        return replace(
            snapshot,
            bridges=bridges,
            bridge_vlans=rules,
            wired=ClientInventory(None, sources, len(hosts), excluded, skipped),
            warnings=tuple(sorted(warnings)),
        )

    clients = []
    for (bridge, mac, vid), rows in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2] or 0)
    ):
        names = sorted({r["on-interface"] for r in rows})
        interface = names[0] if len(names) == 1 else None
        port = ports.get(interface)
        dynamic_values, external_values = (
            {boolean(r.get(field)) for r in rows} for field in ("dynamic", "external")
        )
        dynamic = next(iter(dynamic_values)) if len(dynamic_values) == 1 else None
        external = next(iter(external_values)) if len(external_values) == 1 else None
        attachment = "physical"
        if len(names) != 1:
            attachment = "ambiguous-fdb"
        elif port is None:
            kind = interfaces.get(interface, {}).get("type")
            aggregate = kind in ("bond", "bonding")  # RouterOS 7 reports type "bond".
            attachment = "aggregate-interface" if aggregate else "unmapped-interface"
        elif not port.enabled or not port.up:
            attachment = "link-down"
        elif members[interface] and (
            any(m.bridge != bridge or m.enabled is False for m in members[interface])
        ):
            attachment = "bridge-membership-conflict"
        elif (
            vid is None
            and bridge_by_name.get(bridge)
            and (bridge_by_name[bridge].vlan_filtering is True)
        ):
            attachment = "vlan-unresolved"
        elif dynamic is not True and external is not True:
            attachment = "static-unverified" if dynamic is False else "learning-unverified"
        if attachment != "physical":
            warnings.add("clients:" + attachment)
        clients.append(
            WiredClient(
                mac,
                bridge,
                interface,
                vid,
                port.port_idx if port else None,
                attachment,
                dynamic,
                external,
                conflicting_interfaces=tuple(names) if len(names) > 1 else (),
            )
        )

    # UniFi cannot encode a bridge namespace inside mac_table: suppress conflicting scopes.
    namespaces = defaultdict(list)
    for idx, client in enumerate(clients):
        namespaces[(client.mac, client.vlan)].append(idx)
    for indexes in namespaces.values():
        if len(indexes) > 1:
            warnings.add("clients:ambiguous-unifi-namespace")
            for idx in indexes:
                clients[idx] = replace(clients[idx], attachment="ambiguous-unifi-namespace")

    logical = {i.name: i for i in snapshot.logical_interfaces}
    scope_cache = {}

    def scope(interface):
        if interface in scope_cache:
            return scope_cache[interface]
        result = None
        vlan = logical.get(interface)
        if vlan and vlan.kind == "vlan" and vlan.vlan_id and vlan.parent in bridge_by_name:
            result = (vlan.parent, vlan.vlan_id)
        elif bridge := bridge_by_name.get(interface):
            if bridge.vlan_filtering is False:
                result = (interface, None)
            elif (
                bridge.vlan_filtering is True
                and bridge.pvid is not None
                and any(
                    r.bridge == interface
                    and interface in (r.current_untagged or ())
                    and any(start <= bridge.pvid <= end for start, end in r.ranges)
                    for r in rules or ()
                )
            ):
                result = (interface, bridge.pvid)
        scope_cache[interface] = result
        return result

    known_macs = {c.mac for c in clients}
    addresses = defaultdict(lambda: defaultdict(set))
    hostnames = defaultdict(set)
    for row in arp or ():
        mac, ip = mac_address(row.get("mac-address")), ipv4(row.get("address"))
        if (
            mac not in known_macs
            or ip is None
            or any(boolean(row.get(f)) is True for f in ("invalid", "disabled"))
        ):
            continue
        if (
            row.get("status") not in ("reachable", "stale", "delay", "probe", "permanent")
            and (boolean(row.get("complete")) is not True)
            or row.get("status") in ("incomplete", "failed")
        ):
            continue
        context = scope(row.get("interface"))
        if context is None:
            warnings.add("arp:scope-unresolved")
            continue
        addresses[(*context, mac)][ip].add("arp")
    server_interfaces = defaultdict(set)
    for row in servers or ():
        if boolean(row.get("disabled")) is not True and boolean(row.get("invalid")) is not True:
            if text(row.get("name")) and text(row.get("interface")):
                server_interfaces[row["name"]].add(row["interface"])
    for row in leases or ():
        if row.get("status") != "bound" or any(
            boolean(row.get(f)) is True for f in ("disabled", "blocked")
        ):
            continue
        mac = mac_address(row.get("active-mac-address") or row.get("mac-address"))
        ip = ipv4(row.get("active-address") or row.get("address"))
        if mac not in known_macs or ip is None:
            continue
        candidates = server_interfaces[row.get("active-server") or row.get("server")]
        context = scope(next(iter(candidates))) if len(candidates) == 1 else None
        if context is None:
            warnings.add("dhcp:scope-unresolved")
            continue
        key = (*context, mac)
        addresses[key][ip].add("dhcp")
        hostname = row.get("host-name")
        if hostname and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?", hostname):
            hostnames[(*key, ip)].add(hostname)
        elif hostname:
            warnings.add("dhcp:hostname-unusable")
    for idx, client in enumerate(clients):
        key = (client.bridge, client.vlan, client.mac)
        choices = addresses[key]
        ip = next(iter(choices)) if len(choices) == 1 else None
        if len(choices) > 1:
            warnings.add("clients:ip-conflict")
        names = hostnames[(*key, ip)] if ip else set()
        if len(names) > 1:
            warnings.add("clients:hostname-conflict")
        clients[idx] = replace(
            client,
            ip=ip,
            ip_candidates=tuple(sorted(choices)[:8]),
            ip_sources=tuple(sorted(choices[ip])) if ip else (),
            hostname=next(iter(names)) if len(names) == 1 else None,
        )
    inventory = ClientInventory(tuple(clients), sources, len(hosts), excluded, skipped)
    return replace(
        snapshot,
        bridges=bridges,
        bridge_vlans=rules,
        wired=inventory,
        warnings=tuple(sorted(warnings)),
    )


class ClientTracker:
    """Continuous FDB observation time; missing rows expire on a complete successful poll."""

    def __init__(self):
        self._seen = {}

    def clear(self):
        self._seen.clear()

    def observe(self, snapshot: DeviceSnapshot, now: float) -> DeviceSnapshot:
        inventory = snapshot.wired
        if inventory is None or inventory.clients is None:
            self.clear()
            return snapshot
        seen, clients = {}, []
        for client in inventory.clients:
            key = (client.bridge, client.mac, client.vlan, client.interface)
            if client.attachment == "physical":
                seen[key] = self._seen.get(key, now)
                client = replace(client, observed_uptime_seconds=max(0, int(now - seen[key])))
            clients.append(client)
        self._seen = seen
        return replace(snapshot, wired=replace(inventory, clients=tuple(clients)))
