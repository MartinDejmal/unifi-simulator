import fcntl
import json
import os
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from mtunifi.profiles import profile


class StateBindingError(ValueError):
    """Fixed messages only; never include persisted values or private keys."""


class State(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    schema_version: Literal[1] = 1
    mac: str
    authkey: SecretStr | None = None
    phase: Literal["factory", "key-received", "exchanging"] = "factory"
    cfgversion: str = Field(default="", max_length=256)
    encryption: Literal["cbc", "gcm"] = "cbc"
    controller_url: str | None = None
    last_inform: float | None = None
    last_attempt: float | None = None
    last_telemetry: float | None = None
    last_error: str | None = None
    profile: str | None = None
    routeros_host: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.:-]{1,253}$")
    # "configured": the operator explicitly chose this (possibly physical) MAC, e.g. the
    # RouterOS LLDP chassis MAC, so the controller can match neighbor/FDB evidence to the device.
    mac_source: Literal["synthetic", "configured"] = "synthetic"

    @field_validator("profile")
    @classmethod
    def valid_profile(cls, value):
        if value is not None:
            profile(value)
        return value

    def check_binding(self, selected_profile: str, routeros_host: str | None):
        previous = self.profile
        if previous is None and (self.controller_url is not None or self.authkey is not None):
            previous = "us8-experimental"  # Existing M0–M4 identities were all US8.
        if previous is not None and previous != selected_profile:
            raise StateBindingError("Profile differs from persisted identity; use separate state")
        if self.routeros_host is not None and self.routeros_host != (
            routeros_host.lower() if routeros_host else None
        ):
            raise StateBindingError("RouterOS target differs from persisted identity")

    def bind(self, selected_profile: str, routeros_host: str | None):
        self.check_binding(selected_profile, routeros_host)
        self.profile = selected_profile
        if routeros_host is not None:
            self.routeros_host = routeros_host.lower()

    @field_validator("mac")
    @classmethod
    def valid_mac(cls, value: str) -> str:
        raw = bytes.fromhex(value.replace(":", ""))
        if len(raw) != 6 or raw[0] & 1:
            raise ValueError("Identity must be a unicast MAC")
        return ":".join(f"{b:02x}" for b in raw)

    @model_validator(mode="after")
    def synthetic_mac_is_local(self):
        if self.mac_source == "synthetic" and int(self.mac[:2], 16) & 2 != 2:
            raise ValueError("Identity must be a locally administered unicast MAC")
        return self

    @field_validator("authkey")
    @classmethod
    def valid_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(bytes.fromhex(value.get_secret_value())) != 16:
            raise ValueError("Invalid adoption key")
        return value

    def public(self) -> dict:
        return self.model_dump(mode="json", exclude={"authkey"}) | {
            "has_private_key": self.authkey is not None,
            "controller_adoption_verified": False,
        }

    def reset_adoption(self):
        """Forget protocol credentials, keeping this emulator's MAC and controller binding."""
        self.authkey = None
        self.phase = "factory"
        self.cfgversion = ""
        self.encryption = "cbc"
        self.last_inform = None
        self.last_attempt = None
        self.last_error = None


class Store:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "identity.json"

    @contextmanager
    def lock(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.directory / ".lock").open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another emulator owns this state directory") from None
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def load(self) -> State:
        return State.model_validate_json(self.path.read_bytes())

    def load_or_create(self, configured_mac: str | None = None) -> State:
        wanted = configured_mac.lower() if configured_mac else None
        if self.path.exists():
            state = self.load()  # Corrupt state must never silently create a new identity.
            if wanted is not None and state.mac != wanted:
                raise StateBindingError("Configured MAC differs from persisted identity")
            return state
        if wanted is not None:
            state = State(mac=wanted, mac_source="configured")
        else:
            mac = bytearray(secrets.token_bytes(6))
            mac[0] = (mac[0] | 2) & 254
            state = State(mac=":".join(f"{b:02x}" for b in mac))
        self.save(state)
        return state

    def save(self, state: State):
        data = state.model_dump(mode="json", exclude={"authkey"})
        data["authkey"] = state.authkey.get_secret_value() if state.authkey else None
        self._atomic_json(self.path, data)

    def save_telemetry(self, summary: dict):
        self._atomic_json(self.directory / "telemetry.json", summary)

    def load_telemetry(self) -> dict | None:
        try:
            data = json.loads((self.directory / "telemetry.json").read_bytes())
        except FileNotFoundError:
            return None
        if not isinstance(data, dict) or not (
            isinstance(data.get("active_clients"), int)
            or (data.get("source") == "routeros" and data.get("active_clients") is None)
        ):
            raise ValueError("Invalid telemetry snapshot")
        return data

    def _atomic_json(self, path: Path, data: dict):
        fd, name = tempfile.mkstemp(prefix=".identity-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, path)  # mkstemp creates mode 0600; replacement is atomic.
            directory_fd = os.open(self.directory, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)
