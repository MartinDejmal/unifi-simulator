"""UniFi identity envelope over explicitly selected synthetic or observed telemetry."""

import time

from mtunifi.config import Settings
from mtunifi.profiles import profile
from mtunifi.scenario import SyntheticSource
from mtunifi.storage import State


def inform(
    settings: Settings,
    state: State,
    uptime: int,
    *,
    inform_url: str | None = None,
    snapshot: dict | None = None,
) -> dict:
    if snapshot is None:
        if settings.telemetry_source != "synthetic":
            raise ValueError("RouterOS telemetry requires a collected snapshot")
        snapshot = SyntheticSource(settings.synthetic_file).snapshot(0, state.mac)
    device_profile = profile(settings.profile)
    return {
        "model": settings.model_code,
        "model_display": device_profile.display,
        "version": settings.device_version or device_profile.version,
        "required_version": device_profile.required_version,
        "mac": state.mac,
        "serial": state.mac.replace(":", "").upper(),
        "hostname": settings.hostname,
        "ip": settings.device_ip,
        "inform_url": inform_url if inform_url is not None else settings.inform_url,
        "default": state.authkey is None,
        "state": 0 if state.authkey is None else 2,
        "cfgversion": state.cfgversion,
        "uptime": uptime,
        "time": int(time.time()),
        "discovery_response": False,
        "isolated": False,
        "locating": False,
        **snapshot,
    }
