"""Summarize `mtunifi probe-routeros` output (stdin) for scripts/setup-mikrotik.sh."""

import json
import sys

text = sys.stdin.read()
try:
    data = json.loads(text[text.index("{") :])
except ValueError:
    print(text)
    sys.exit(1)
if data.get("event") == "startup_error":
    print("Probe failed:", data.get("reason"), "-", data.get("hint"))
    sys.exit(1)
observations = data.get("observations") or {}
print("Status:", data.get("status"), "| warnings:", observations.get("warnings"))
for port in observations.get("ports") or []:
    print(
        f"  slot {port['port_idx']:>2} {port['name']:<14} "
        f"up={port['up']} speed={port['speed_mbps']}"
    )
