"""Print observed PoE per port from `mtunifi probe-routeros` output on stdin."""

import json
import sys

text = sys.stdin.read()
data = json.loads(text[text.index("{") :])
observations = data.get("observations") or {}
print("status", data.get("status"), observations.get("warnings"))
for port in observations.get("ports") or []:
    print(port.get("port_idx"), port.get("name"), port.get("up"), port.get("poe"))
