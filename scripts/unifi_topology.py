"""Summarize UniFi stat/device JSON (stdin): uplinks and LLDP neighbors only, no secrets."""

import json
import sys

devices = json.load(sys.stdin).get("data", [])
for d in sorted(devices, key=lambda x: x.get("name") or x.get("model") or ""):
    uplink = d.get("uplink") or {}
    print(
        f"== {d.get('name') or '-'}  model={d.get('model')}  mac={d.get('mac')}  "
        f"state={d.get('state')}  adopted={d.get('adopted')}"
    )
    print(
        "   firmware:",
        {k: d.get(k) for k in ("version", "upgradable", "upgrade_to_firmware") if k in d},
    )
    power = {
        k: v
        for k, v in d.items()
        if any(t in k.lower() for t in ("poe", "power", "budget"))
        and not isinstance(v, (list, dict))
    }
    if power:
        print("   power:", power)
    print(
        "   uplink:",
        {
            k: uplink.get(k)
            for k in (
                "type",
                "uplink_mac",
                "uplink_device_name",
                "uplink_remote_port",
                "port_idx",
                "name",
            )
            if uplink.get(k) is not None
        },
    )
    for key in ("last_uplink", "uplink_table"):
        if d.get(key):
            print(f"   {key}:", d.get(key))
    for n in d.get("lldp_table") or []:
        print(
            "   lldp:",
            n.get("local_port_idx"),
            n.get("local_port_name"),
            "->",
            n.get("chassis_id"),
            n.get("port_id"),
            (n.get("chassis_descr") or "")[:40],
        )
    downlinks = d.get("downlink_table") or []
    if downlinks:
        print("   downlinks:", [(x.get("port_idx"), x.get("mac")) for x in downlinks])
    # Aggregation-related port fields (to mirror how a real switch reports a LAG).
    for p in d.get("port_table") or []:
        keys = {k: v for k, v in p.items() if any(t in k for t in ("agg", "lag", "lacp"))}
        if any(keys.values()) or p.get("op_mode") not in (None, "switch"):
            print(
                "   port",
                p.get("port_idx"),
                {"op_mode": p.get("op_mode"), "is_uplink": p.get("is_uplink"), **keys},
            )
    # PoE port fields (to mirror how a real PoE switch reports them).
    for p in d.get("port_table") or []:
        poe = {k: v for k, v in p.items() if "poe" in k}
        if poe.get("port_poe"):
            print("   poe", p.get("port_idx"), poe)
