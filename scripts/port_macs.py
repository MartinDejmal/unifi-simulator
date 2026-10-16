"""Print per-port MAC tables from `mtunifi diagnose` JSON on stdin (what the switch reports)."""

import json
import sys

data = json.load(sys.stdin)
observations = (data.get("routeros_telemetry") or {}).get("observations") or {}
clients = (observations.get("wired") or {}).get("clients") or []
by_port: dict = {}
for client in clients:
    if client.get("attachment") == "physical":
        by_port.setdefault(client.get("port_idx"), []).append(client.get("mac"))
neighbors = (observations.get("neighbors") or {}).get("observations") or []
for n in neighbors:
    if n.get("export_reason") == "eligible":
        print("neighbor", n.get("port_idx"), n.get("mac"), n.get("identity"))
for port, macs in sorted(by_port.items(), key=lambda kv: kv[0] or 0):
    print("fdb port", port, len(macs))
print("uplink_neighbor_mac", observations.get("uplink_neighbor_mac"))
print("warnings", observations.get("warnings"))
for i in observations.get("logical_interfaces") or []:
    if i.get("kind") == "bonding":
        print("bond", i.get("name"), i.get("members"))
