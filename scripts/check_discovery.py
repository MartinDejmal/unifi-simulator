"""Read-only check of automatic discovery: ether1 MAC and the automatic port map.

Run inside the emulator image with the device's environment, e.g.
docker compose ... run --rm --no-deps --entrypoint python <service> scripts/check_discovery.py
"""

import asyncio

from mtunifi.config import Settings
from mtunifi.routeros import auto_mapping, discover_device_mac
from mtunifi.routeros_api import RouterOSAPI


async def main():
    settings = Settings.from_env()
    print("device_mac", await discover_device_mac(settings))
    async with RouterOSAPI(settings) as api:
        mapping = await auto_mapping(api, settings.profile)
    for port in mapping.ports:
        print("slot", port.port_idx, port.interface, "uplink" if port.is_uplink else "")


asyncio.run(main())
