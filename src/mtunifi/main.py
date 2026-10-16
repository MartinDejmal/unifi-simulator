import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

from pydantic import ValidationError

from mtunifi.config import Settings
from mtunifi.emulator import Emulator
from mtunifi.profiles import profile
from mtunifi.routeros import discover_device_mac
from mtunifi.routeros_api import RouterOSError, api_target
from mtunifi.scenario import ScenarioError, SyntheticSource
from mtunifi.sources import create_source
from mtunifi.storage import StateBindingError, Store
from mtunifi.telemetry import inform


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental UniFi device protocol emulator")
    parser.add_argument(
        "command",
        choices=(
            "init",
            "sample",
            "run",
            "diagnose",
            "health",
            "validate-scenario",
            "reset-adoption",
            "probe-routeros",
            "validate-inventory",
        ),
    )
    parser.add_argument("--once", action="store_true", help="Run one inform; nonzero on failure")
    parser.add_argument("--inventory", type=Path, help="Independent device settings in a JSON file")
    parser.add_argument("--device", help="Select one inventory device by its stable ID")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    try:
        if args.inventory is not None:
            from mtunifi.fleet import fleet_command

            return fleet_command(args.inventory, args.command, args.device, args.once)
        if args.device is not None or args.command == "validate-inventory":
            raise ValueError("An inventory is required")
        settings = Settings.from_env()
        if args.command == "probe-routeros":
            if settings.telemetry_source != "routeros":
                raise ValueError("Select RouterOS collection to probe the API")
            source = create_source(settings)
            asyncio.run(source.collect(time.monotonic(), ""))
            print(json.dumps(source.last_summary, indent=2))
            return 0
        if args.command == "validate-scenario":
            source = SyntheticSource(settings.synthetic_file)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "ports": len(source.scenario.ports),
                        "clients": len(source.scenario.clients),
                        "neighbors": len(source.scenario.neighbors),
                    }
                )
            )
            return 0
        store = Store(settings.state_dir)
        if args.command == "reset-adoption":
            with store.lock():
                state = store.load()  # Never manufacture an identity when resetting missing state.
                state.check_binding(
                    settings.profile,
                    settings.routeros_host if settings.telemetry_source == "routeros" else None,
                )
                if state.controller_url not in (None, settings.inform_url):
                    raise RuntimeError("State belongs to another controller")
                state.reset_adoption()
                store.save(state)
                print(
                    json.dumps(
                        {
                            "event": "adoption_reset",
                            "reason": "operator",
                            "mac": state.mac,
                            "phase": state.phase,
                            "has_private_key": False,
                        }
                    )
                )
            return 0
        if args.command in ("diagnose", "health"):
            state = store.load()
            state.check_binding(
                settings.profile,
                settings.routeros_host if settings.telemetry_source == "routeros" else None,
            )
            age = time.time() - state.last_inform if state.last_inform else None
            telemetry = store.load_telemetry()
            if telemetry and telemetry.get("source") != settings.telemetry_source:
                telemetry = None
            routeros = settings.telemetry_source == "routeros"
            source_ready = not routeros or (
                telemetry is not None
                and telemetry.get("source") == "routeros"
                and telemetry.get("status") in ("active", "degraded")
                and telemetry.get("observed_at") is not None
                and 0
                <= time.time() - telemetry["observed_at"]
                <= settings.routeros_poll_interval * 3 + settings.routeros_timeout
            )
            if args.command == "health":
                return (
                    0
                    if (
                        age is not None
                        and 0 <= age <= 660
                        and state.last_error is None
                        and state.controller_url == settings.inform_url
                        and source_ready
                    )
                    else 1
                )
            observations = telemetry.get("observations") if telemetry and routeros else None
            routeros_status = (
                (telemetry.get("status", "unavailable") if telemetry else "unavailable")
                if routeros
                else "disabled"
            )
            print(
                json.dumps(
                    state.public()
                    | {
                        "controller": settings.inform_url,
                        "selected_profile": settings.profile,
                        "model": settings.model_code,
                        "wan_interface": settings.routeros_wan_interface
                        if profile(settings.profile).kind == "gateway"
                        else None,
                        "wan": observations.get("wan") if observations else None,
                        "last_inform_age_seconds": age,
                        "routeros": routeros_status,
                        "telemetry_source": settings.telemetry_source,
                        "discovered_ports": len(observations["ports"]) if observations else 0,
                        "synthetic_ports": 0 if routeros else 8,
                        "wired_clients": (
                            telemetry["active_clients"] if telemetry else None if routeros else 0
                        ),
                        "wired_clients_source": "routeros-fdb" if routeros else "synthetic",
                        "neighbors": telemetry.get("neighbors") if telemetry else None,
                        "neighbors_source": "routeros-neighbor-cache" if routeros else "synthetic",
                        "synthetic_telemetry": None if routeros else telemetry,
                        "routeros_telemetry": telemetry if routeros else None,
                        "adoption_note": (
                            "Exchanging is a protocol state; verify adoption in controller UI"
                        ),
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "sample" and settings.telemetry_source != "synthetic":
            raise ValueError("Use probe-routeros for observed telemetry")
        source = create_source(settings) if args.command != "init" else None
        with store.lock():
            configured_mac = settings.device_mac
            if configured_mac == "auto":
                # Read once for a new identity; an existing identity keeps its MAC.
                configured_mac = (
                    None if store.path.exists() else asyncio.run(discover_device_mac(settings))
                )
            state = store.load_or_create(configured_mac)
            state.bind(
                settings.profile,
                settings.routeros_host if settings.telemetry_source == "routeros" else None,
            )
            if args.command == "init":
                print(json.dumps(state.public(), indent=2))
            elif args.command == "sample":
                snapshot = source.snapshot(0, state.mac)
                print(json.dumps(inform(settings, state, 0, snapshot=snapshot), indent=2))
            else:
                return (
                    0 if asyncio.run(Emulator(settings, store, state, source).run(args.once)) else 1
                )
    except (OSError, ValidationError, ValueError, RuntimeError) as exc:
        # Validation errors can echo input, including secrets from corrupt state.
        details = (
            {"reason": str(exc), "issues": exc.issues} if isinstance(exc, ScenarioError) else {}
        )
        if isinstance(exc, RouterOSError):
            details = exc.public() | {"routeros_target": api_target(settings)}
        if isinstance(exc, StateBindingError):
            details = {
                "reason": str(exc),
                "hint": (
                    "Use the same Compose overrides, telemetry source, RouterOS host "
                    "and profile as this state volume. reset-adoption preserves these bindings. "
                    "See docs/adoption.md."
                ),
            }
        from mtunifi.fleet import InventoryError

        if isinstance(exc, InventoryError):
            details = {"reason": str(exc)}
        print(
            json.dumps(
                {
                    "event": "startup_error",
                    "category": type(exc).__name__,
                    "hint": "Check configuration, state permissions and exclusive ownership",
                }
                | details
            ),
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
