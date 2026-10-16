"""Print device MAC and RouterOS neighbor observations from `mtunifi diagnose` JSON on stdin."""

import json
import sys

data = json.load(sys.stdin)
print("device_mac", data.get("mac"))
observations = (data.get("routeros_telemetry") or {}).get("observations") or {}
for row in (observations.get("neighbors") or {}).get("observations") or []:
    print(
        row.get("interfaces"),
        row.get("protocols"),
        row.get("mac"),
        row.get("identity"),
        row.get("remote_port"),
        row.get("export_reason"),
    )
