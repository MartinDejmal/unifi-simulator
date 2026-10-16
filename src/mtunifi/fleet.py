"""Bounded inventory and process supervision; each device keeps its own CLI/runtime."""

import asyncio
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from mtunifi.config import Settings
from mtunifi.routeros import AUTO_MAP
from mtunifi.scenario import LabModel
from mtunifi.storage import Store

MAX_INVENTORY = 64 * 1024
MAX_OUTPUT = 16 * 1024 * 1024


class InventoryError(ValueError):
    """Only fixed messages, never raw input/validation/worker output."""


class Device(LabModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$")
    settings: Settings

    @model_validator(mode="after")
    def explicit_identity(self):
        if not {"state_dir", "hostname", "device_ip"} <= self.settings.model_fields_set:
            raise ValueError("Each device needs explicit state, hostname and advertised IP")
        return self


class Inventory(LabModel):
    schema_version: Literal[1] = 1
    devices: list[Device] = Field(min_length=1, max_length=32)


def load_inventory(path: Path) -> Inventory:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_INVENTORY + 1)
        if len(data) > MAX_INVENTORY:
            raise InventoryError("Inventory exceeds size limit")
        inventory = Inventory.model_validate_json(data)
    except (OSError, ValidationError):
        raise InventoryError(
            "Cannot read or validate inventory; check the documented schema"
        ) from None
    directories = []
    ids, addresses, hostnames, targets = set(), set(), set(), set()
    for device in inventory.devices:
        settings = device.settings
        for field in (
            "state_dir",
            "synthetic_file",
            "routeros_password_file",
            "routeros_ca_file",
            "routeros_map_file",
        ):
            value = getattr(settings, field)
            if value is not None and value != AUTO_MAP:
                setattr(settings, field, (path.resolve().parent / value).resolve())
        directory = settings.state_dir
        if any(
            directory == d or directory in d.parents or d in directory.parents for d in directories
        ):
            raise InventoryError("State directories must be separate and must not overlap")
        address = (settings.inform_url, settings.device_ip)
        hostname = (settings.inform_url, settings.hostname.lower())
        if device.id in ids or address in addresses or hostname in hostnames:
            raise InventoryError("Device IDs, advertised IPs and hostnames must be unique")
        if settings.telemetry_source == "routeros":
            target = (settings.routeros_host.lower(), settings.routeros_port, settings.routeros_tls)
            if target in targets:
                raise InventoryError("Each RouterOS target may occur only once per inventory")
            targets.add(target)
        directories.append(directory)
        ids.add(device.id)
        addresses.add(address)
        hostnames.add(hostname)
    return inventory


def check_existing_identities(devices: list[Device]):
    identities = set()
    for device in devices:
        store = Store(device.settings.state_dir)
        if not store.path.exists():
            continue
        try:
            state = store.load()
        except (OSError, ValueError):
            # A corrupt/inaccessible state is reported by its worker, without stopping peers.
            continue
        if state.mac in identities:
            raise InventoryError("Copied device identity detected; do not share or clone state")
        identities.add(state.mac)


def environment(settings: Settings) -> dict[str, str]:
    # Inherited single-device settings must never silently bind a second worker to the first.
    result = {k: v for k, v in os.environ.items() if not k.startswith("MTUNIFI_")}
    result.update(
        {
            "MTUNIFI_" + key.upper(): str(value)
            for key, value in settings.model_dump(mode="json").items()
            if value is not None
        }
    )
    return result


def event(device_id: str, name: str, **fields):
    print(
        json.dumps({"event": name, **fields, "device_id": device_id}), file=sys.stderr, flush=True
    )


async def stop_process(process):
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), 5)
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()


async def pipe_events(stream, device_id: str):
    while True:
        try:
            line = await stream.readline()
        except (ValueError, asyncio.LimitOverrunError):
            raise InventoryError("Worker output line exceeds limit") from None
        if not line:
            return
        try:
            record = json.loads(line)
            if not isinstance(record, dict) or not isinstance(record.get("event"), str):
                raise ValueError
        except (ValueError, UnicodeError):
            # Tracebacks/arbitrary child output can contain data: never forward them verbatim.
            event(device_id, "worker_output_rejected")
        else:
            print(json.dumps(record | {"device_id": device_id}), file=sys.stderr, flush=True)


async def launch(device: Device, command: str, once: bool = False):
    arguments = [sys.executable, "-m", "mtunifi.main", command]
    if once:
        arguments.append("--once")
    return await asyncio.create_subprocess_exec(
        *arguments,
        env=environment(device.settings),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=64 * 1024,
    )


async def supervise(device: Device, stop: asyncio.Event, once: bool) -> bool:
    failures = 0
    while not stop.is_set():
        process = None
        pending = []
        began = time.monotonic()
        try:
            process = await launch(device, "run", once)
            event(device.id, "worker_started", pid=process.pid, profile=device.settings.profile)
            pending = [
                asyncio.create_task(pipe_events(s, device.id))
                for s in (process.stdout, process.stderr)
            ]
            exited = asyncio.create_task(process.wait())
            stopping = asyncio.create_task(stop.wait())
            pending.extend((exited, stopping))
            done, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if stopping in done:
                return False
            for task in done:
                task.result()
            # EOF on a stream can precede wait(); await exit while still servicing stop.
            if exited not in done:
                await asyncio.wait((exited, stopping), return_when=asyncio.FIRST_COMPLETED)
                if stop.is_set():
                    return False
            await asyncio.gather(*pending[:2])
            if once:
                return process.returncode == 0
            event(device.id, "worker_exited", exit_code=process.returncode)
        except (OSError, ValueError):
            event(device.id, "worker_failed", reason="worker-runtime-error")
            if once:
                return False
        finally:
            if process is not None:
                await stop_process(process)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        if stop.is_set():
            break
        failures = 1 if time.monotonic() - began > 60 else min(4, failures + 1)
        delay = min(30, 5 * 2 ** (failures - 1))
        event(device.id, "worker_retry", retry_seconds=delay)
        try:
            await asyncio.wait_for(stop.wait(), delay)
        except TimeoutError:
            pass
    return False


async def run_devices(devices: list[Device], once: bool) -> bool:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signum, stop.set)
            installed.append(signum)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        results = await asyncio.gather(*(supervise(d, stop, once) for d in devices))
        return all(results) if once else stop.is_set()
    finally:
        for signum in installed:
            loop.remove_signal_handler(signum)


async def capture(device: Device, command: str) -> dict:
    process = None
    try:
        process = await launch(device, command)

        async def read_bounded(stream):
            chunks, size = [], 0
            while chunk := await stream.read(64 * 1024):
                size += len(chunk)
                if size > MAX_OUTPUT:
                    raise InventoryError("Worker output exceeds limit")
                chunks.append(chunk)
            return b"".join(chunks)

        async with asyncio.timeout(device.settings.timeout + device.settings.routeros_timeout + 30):
            out, err = await asyncio.gather(
                read_bounded(process.stdout), read_bounded(process.stderr)
            )
            await process.wait()
        if process.returncode == 0:
            data = json.loads(out) if out.strip() else None
        else:
            data = None
            for line in err.splitlines():
                try:
                    record = json.loads(line)
                    if isinstance(record, dict) and record.get("event") == "startup_error":
                        data = record
                except (ValueError, UnicodeError):
                    pass
        return {"device_id": device.id, "exit_code": process.returncode, "result": data}
    except (OSError, ValueError, TimeoutError):
        return {"device_id": device.id, "exit_code": 2, "error": "worker-command-failed"}
    finally:
        if process is not None:
            await stop_process(process)


async def capture_devices(devices: list[Device], command: str) -> list[dict]:
    return await asyncio.gather(*(capture(d, command) for d in devices))


def fleet_command(path: Path, command: str, device_id: str | None, once: bool) -> int:
    inventory = load_inventory(path)
    devices = [d for d in inventory.devices if device_id is None or d.id == device_id]
    if not devices:
        raise InventoryError("Unknown inventory device ID")
    if command == "validate-inventory":
        print(
            json.dumps(
                {
                    "valid": True,
                    "devices": [
                        {
                            "id": d.id,
                            "profile": d.settings.profile,
                            "model": d.settings.model_code,
                        }
                        for d in devices
                    ],
                }
            )
        )
        return 0
    if command == "reset-adoption" and device_id is None:
        raise InventoryError("Select exactly one device for reset-adoption with --device")
    if command == "validate-scenario":
        raise InventoryError("Validate synthetic scenarios with the single-device CLI")
    if command in ("run", "init"):
        check_existing_identities(inventory.devices)
    if command == "run":
        return 0 if asyncio.run(run_devices(devices, once)) else 1
    records = asyncio.run(capture_devices(devices, command))
    print(json.dumps({"devices": records}, indent=2))
    return 0 if all(r["exit_code"] == 0 for r in records) else 1
