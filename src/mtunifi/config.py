import ipaddress
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mtunifi.profiles import profile


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    inform_url: str = "http://127.0.0.1:8080/inform"
    state_dir: Path = Path(".state")
    device_ip: str = "192.0.2.10"
    hostname: str = Field(default="mtunifi-lab", pattern=r"^[A-Za-z0-9-]{1,63}$")
    profile: str = "us8-experimental"
    # Report the RouterOS identity (when it is a valid hostname) instead of `hostname`.
    hostname_from_identity: bool = False
    # Switches: also report the management interface (uplink "eth0" + if_table), as real
    # UniFi switches do, so the controller can build this device's own uplink.
    report_uplink: bool = False
    # Mark ports bonded in RouterOS as a UniFi LAG (display only; nothing is configured).
    report_lag: bool = False
    # Read PoE-out state of RJ45 ports (/interface/ethernet/poe/monitor, read-only).
    routeros_poe: bool = False
    # Total PoE-out budget reported to the controller (W); usage is summed from the ports.
    poe_budget_w: float | None = Field(default=None, gt=0, le=10000)
    # Optional UniFi model code overriding the profile's (e.g. to try another gateway model).
    device_model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9]{2,16}$")
    # Optional firmware version reported to the controller (e.g. its current release for
    # the model, so it stops offering an upgrade); defaults to the profile's version.
    device_version: str | None = Field(default=None, pattern=r"^\d{1,4}(\.\d{1,8}){1,4}$")
    # Optional explicit device MAC (e.g. the RouterOS LLDP chassis MAC) instead of a synthetic one.
    device_mac: str | None = Field(default=None, pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    packet_version: int = Field(default=1, ge=0, le=1)
    encryption: str = "cbc"
    interval: float = Field(default=10, ge=1, le=300)
    timeout: float = Field(default=10, ge=1, le=120)
    trace: bool = False
    synthetic_file: Path | None = None
    telemetry_source: Literal["synthetic", "routeros"] = "synthetic"
    routeros_host: str | None = None
    routeros_port: int = Field(default=8729, ge=1, le=65535)
    routeros_tls: bool = True
    routeros_user: str | None = Field(default=None, min_length=1, max_length=128, repr=False)
    routeros_password_file: Path | None = None
    routeros_ca_file: Path | None = None
    routeros_map_file: Path | None = None
    routeros_timeout: float = Field(default=10, ge=1, le=120)
    routeros_poll_interval: float = Field(default=10, ge=5, le=300)
    routeros_wan_interface: str = Field(default="ether1", min_length=1, max_length=128)
    # Optional second WAN (e.g. a backup line); exported as the gateway's wan2 (eth2).
    routeros_wan2_interface: str | None = Field(default=None, min_length=1, max_length=128)
    # Also export MNDP/CDP and merged-protocol neighbors, and LLDP seen on bond members.
    routeros_neighbors_relaxed: bool = False
    # List the single ARP neighbor on the uplink port (e.g. ISP gateway) as the parent.
    routeros_uplink_from_arp: bool = False
    # Also announce that gateway as a derived (not received) LLDP neighbor on the uplink port.
    routeros_uplink_lldp_from_arp: bool = False
    # Neighbor MAC rewrites "real=reported,..." (e.g. another emulated MikroTik's port MAC
    # to that emulator's device MAC) so both ends of a link name the same chassis.
    routeros_neighbor_mac_aliases: str | None = Field(default=None, max_length=1024)

    @field_validator("routeros_wan_interface", "routeros_wan2_interface")
    @classmethod
    def interface_name(cls, value):
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Control characters are not allowed")
        return value

    @field_validator(
        "synthetic_file",
        "routeros_password_file",
        "routeros_ca_file",
        "routeros_map_file",
        "routeros_wan2_interface",
        "device_model",
        "device_version",
        "device_mac",
        "poe_budget_w",
        "routeros_neighbor_mac_aliases",
        mode="before",
    )
    @classmethod
    def optional_scenario(cls, value):
        return None if value == "" else value

    @field_validator("routeros_host")
    @classmethod
    def valid_routeros_host(cls, value):
        if value is None:
            return value
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            if (
                not value
                or len(value) > 253
                or any(
                    c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
                    for c in value
                )
            ):
                raise ValueError("Expected a hostname or IP, without URL or port") from None
        return value

    @field_validator("routeros_user")
    @classmethod
    def valid_routeros_user(cls, value):
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Control characters are not allowed")
        return value

    @field_validator("device_mac")
    @classmethod
    def unicast_mac(cls, value):
        if value is not None and int(value[:2], 16) & 1:
            raise ValueError("Device MAC must be unicast")
        return value.lower() if value else value

    @property
    def neighbor_mac_aliases(self) -> dict[str, str]:
        result = {}
        for pair in (self.routeros_neighbor_mac_aliases or "").split(","):
            if not pair.strip():
                continue
            real, _, reported = pair.partition("=")
            pattern = r"([0-9a-f]{2}:){5}[0-9a-f]{2}"
            real, reported = real.strip().lower(), reported.strip().lower()
            if not re.fullmatch(pattern, real) or not re.fullmatch(pattern, reported):
                raise ValueError("Neighbor MAC aliases must be real=reported MAC pairs")
            result[real] = reported
        return result

    @property
    def model_code(self) -> str:
        return self.device_model or profile(self.profile).model

    @model_validator(mode="after")
    def source_settings(self):
        if self.profile != "us8-experimental" and self.telemetry_source != "routeros":
            raise ValueError("This profile requires RouterOS telemetry")
        if self.telemetry_source == "routeros":
            if not all(
                (
                    self.routeros_host,
                    self.routeros_user,
                    self.routeros_password_file,
                )
            ):
                raise ValueError("RouterOS host, user and password file are required")
            if profile(self.profile).kind == "switch" and self.routeros_map_file is None:
                raise ValueError("Switch collection requires a port map")
            if self.synthetic_file is not None:
                raise ValueError("Select either a synthetic scenario or RouterOS collection")
        return self

    @field_validator("inform_url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/inform"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Use an HTTP(S) /inform URL without credentials, query or fragment")
        _ = parsed.port
        return value

    @field_validator("device_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value))

    @field_validator("encryption")
    @classmethod
    def valid_mode(cls, value: str) -> str:
        if value not in ("cbc", "gcm"):
            raise ValueError("Expected cbc or gcm")
        return value

    @field_validator("profile")
    @classmethod
    def valid_profile(cls, value: str) -> str:
        profile(value)
        return value

    @classmethod
    def from_env(cls) -> "Settings":
        return cls.model_validate(
            {
                name: os.environ[f"MTUNIFI_{name.upper()}"]
                for name in cls.model_fields
                if f"MTUNIFI_{name.upper()}" in os.environ
            }
        )
