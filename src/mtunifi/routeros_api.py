"""Bounded RouterOS 7 API transport. Only the commands below can reach the wire."""

import asyncio
import errno
import socket
import ssl
from enum import StrEnum
from pathlib import Path

from mtunifi.config import Settings

MAX_WORD = 64 * 1024
MAX_REPLY = 4 * 1024 * 1024
MAX_ROWS = 4096


class RouterOSError(ValueError):
    """Fixed safe codes only; never include server messages or credentials."""

    def __init__(self, code: str, *, stage: str | None = None, error_number: int | None = None):
        self.code = code
        self.stage = stage
        self.error_number = error_number
        super().__init__("RouterOS " + code)

    def public(self) -> dict:
        hints = {
            "connection-refused": "Check API service/port and rejecting firewall rules",
            "dns-resolution-failed": "Check the RouterOS hostname and container DNS",
            "network-unreachable": "Check container routing, LAN/VPN access and firewall rules",
            "connection-reset": "Peer reset the session; check API service and allowed source IP",
            "connection-closed": (
                "Peer closed the session; check API service, allowed source IP and transport/port"
            ),
            "tls-verification-failed": "Check trusted CA, certificate validity and hostname",
            "tls-config-invalid": "Check CA file path, permissions and PEM contents",
            "tls-handshake-failed": "Check API-SSL service and matching TLS/port settings",
            "timeout": "Check reachability, API response time and the collection timeout budget",
            "authentication-failed": "Check the read-only API account and local password file",
            "password-file-invalid": "Check the mounted password file and UID 10001 read access",
            "wan-interface-missing": "Check the configured WAN interface name on RouterOS",
            "required-wan-data-missing": "Check WAN link flags and absolute interface counters",
        }
        return {
            "reason": str(self),
            "stage": self.stage,
            "errno": self.error_number,
            "hint": hints.get(
                self.code, "Check RouterOS API configuration and read-only permissions"
            ),
        }


def api_target(settings: Settings) -> dict:
    # Configuration rejects credential-bearing URLs; never include username or secret paths.
    return {
        "host": settings.routeros_host,
        "port": settings.routeros_port,
        "tls": settings.routeros_tls,
    }


def api_error(exc: Exception, stage: str) -> RouterOSError:
    if isinstance(exc, RouterOSError):
        return RouterOSError(exc.code, stage=exc.stage or stage, error_number=exc.error_number)
    if isinstance(exc, ssl.SSLCertVerificationError):
        code = "tls-verification-failed"
    elif isinstance(exc, ssl.SSLError):
        code = "tls-handshake-failed"
    elif isinstance(exc, socket.gaierror):
        code = "dns-resolution-failed"
    elif isinstance(exc, TimeoutError):
        code = "timeout"
    elif isinstance(exc, asyncio.IncompleteReadError):
        code = "connection-closed"
    elif isinstance(exc, OSError):
        code = {
            errno.ECONNREFUSED: "connection-refused",
            errno.ECONNRESET: "connection-reset",
            errno.EPIPE: "connection-closed",
            errno.EHOSTUNREACH: "network-unreachable",
            errno.ENETUNREACH: "network-unreachable",
            errno.ETIMEDOUT: "timeout",
        }.get(exc.errno, "connection-failed")
    else:
        code = "connection-failed"
    number = exc.errno if isinstance(exc, OSError) and isinstance(exc.errno, int) else None
    return RouterOSError(code, stage=stage, error_number=number)


class Table(StrEnum):
    RESOURCE = "/system/resource/print"
    IDENTITY = "/system/identity/print"
    INTERFACES = "/interface/print"
    ETHERNET = "/interface/ethernet/print"
    BRIDGE_PORTS = "/interface/bridge/port/print"
    VLANS = "/interface/vlan/print"
    BONDS = "/interface/bonding/print"
    BRIDGES = "/interface/bridge/print"
    BRIDGE_VLANS = "/interface/bridge/vlan/print"
    BRIDGE_HOSTS = "/interface/bridge/host/print"
    ARP = "/ip/arp/print"
    DHCP_LEASES = "/ip/dhcp-server/lease/print"
    DHCP_SERVERS = "/ip/dhcp-server/print"
    NEIGHBORS = "/ip/neighbor/print"
    IP_ADDRESSES = "/ip/address/print"


PROPERTIES = {
    Table.RESOURCE: "version,uptime,cpu-load,total-memory,free-memory,board-name,architecture-name",
    Table.IDENTITY: "name",
    Table.INTERFACES: ".id,name,type,mac-address,disabled,running,rx-byte,tx-byte",
    Table.ETHERNET: ".id,name,default-name,mac-address,disabled,running",
    Table.BRIDGE_PORTS: "interface,bridge,hw,hw-offload,disabled,pvid",
    Table.VLANS: "name,interface,vlan-id",
    Table.BONDS: "name,slaves,mode",
    Table.BRIDGES: "name,mac-address,admin-mac,vlan-filtering,pvid,ageing-time",
    Table.BRIDGE_VLANS: (
        "bridge,vlan-ids,tagged,untagged,current-tagged,current-untagged,dynamic,disabled"
    ),
    Table.BRIDGE_HOSTS: (
        "mac-address,vid,on-interface,bridge,local,dynamic,external,invalid,disabled"
    ),
    Table.ARP: "address,mac-address,interface,status,complete,invalid,disabled",
    Table.DHCP_LEASES: (
        "address,mac-address,active-address,active-mac-address,active-server,host-name,status,"
        "server,disabled,blocked"
    ),
    Table.DHCP_SERVERS: "name,interface,disabled,invalid",
    Table.NEIGHBORS: (
        "interface,mac-address,identity,interface-name,discovered-by,age,system-description"
    ),
    Table.IP_ADDRESSES: "address,interface,actual-interface,disabled,invalid,dynamic",
}
MONITOR = "/interface/ethernet/monitor"
POE_MONITOR = "/interface/ethernet/poe/monitor"


def length_prefix(size: int) -> bytes:
    if not 0 <= size <= MAX_WORD:
        raise RouterOSError("word-too-large")
    if size < 0x80:
        return bytes([size])
    if size < 0x4000:
        return (size | 0x8000).to_bytes(2, "big")
    return (size | 0xC00000).to_bytes(3, "big")


async def read_word(reader: asyncio.StreamReader) -> bytes:
    first = (await reader.readexactly(1))[0]
    if first < 0x80:
        size = first
    elif first < 0xC0:
        size = ((first & 0x3F) << 8) | int.from_bytes(await reader.readexactly(1), "big")
    elif first < 0xE0:
        size = ((first & 0x1F) << 16) | int.from_bytes(await reader.readexactly(2), "big")
    elif first < 0xF0:
        size = ((first & 0x0F) << 24) | int.from_bytes(await reader.readexactly(3), "big")
    elif first == 0xF0:
        size = int.from_bytes(await reader.readexactly(4), "big")
    else:
        raise RouterOSError("invalid-length")
    if size > MAX_WORD:
        raise RouterOSError("word-too-large")
    return await reader.readexactly(size)


def read_password(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(4097)
        # Permit one final newline from a secret file, preserving spaces in passwords.
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        if not raw or len(raw) > 4096 or any(c in raw for c in (b"\n", b"\r", b"\0")):
            raise ValueError
        return raw.decode("utf-8")
    except (OSError, ValueError):
        raise RouterOSError("password-file-invalid") from None


class RouterOSAPI:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.stage = "connect"

    async def __aenter__(self):
        try:
            context = None
            if self.settings.routeros_tls:
                self.stage = "tls-configuration"
                try:
                    context = ssl.create_default_context(cafile=self.settings.routeros_ca_file)
                except (OSError, ssl.SSLError):
                    raise RouterOSError("tls-config-invalid") from None
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.stage = "connect-tls" if context else "connect"
            self.reader, self.writer = await asyncio.open_connection(
                self.settings.routeros_host,
                self.settings.routeros_port,
                ssl=context,
                server_hostname=self.settings.routeros_host if context else None,
                limit=MAX_WORD + 1,
            )
            self.stage = "credentials"
            password = read_password(self.settings.routeros_password_file)
            await self._execute(
                "/login", ("=name=" + self.settings.routeros_user, "=password=" + password)
            )
            return self
        except BaseException:
            await self.close()
            raise

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            try:
                async with asyncio.timeout(1):
                    await self.writer.wait_closed()
            except (OSError, TimeoutError):
                pass
            self.writer = None

    async def table(self, table: Table) -> list[dict[str, str]]:
        if not isinstance(table, Table):
            raise RouterOSError("command-not-allowed")
        words = ["=.proplist=" + PROPERTIES[table]]
        if table == Table.INTERFACES:
            words.append("=stats=")
        return await self._execute(table.value, tuple(words))

    async def monitor(self, interface_id: str) -> list[dict[str, str]]:
        if not interface_id or len(interface_id) > 128 or any(ord(c) < 32 for c in interface_id):
            raise RouterOSError("invalid-interface-id")
        return await self._execute(MONITOR, ("=numbers=" + interface_id, "=once="))

    async def poe_monitor(self, names: tuple[str, ...]) -> list[dict[str, str]]:
        """Read-only PoE-out status (state, voltage, current, power) of the named ports."""
        if not names or any(
            not n or len(n) > 64 or "," in n or any(ord(c) < 32 for c in n) for n in names
        ):
            raise RouterOSError("invalid-interface-id")
        return await self._execute(POE_MONITOR, ("=numbers=" + ",".join(names), "=once="))

    async def _execute(self, command: str, words: tuple[str, ...]) -> list[dict[str, str]]:
        # Defense in depth: even internal callers cannot send writes, scripts or arbitrary paths.
        if command not in {"/login", MONITOR, POE_MONITOR, *(t.value for t in Table)}:
            raise RouterOSError("command-not-allowed")
        self.stage = command  # Allowlisted path only; never retain argument words or passwords.
        if self.writer is None or self.reader is None:
            raise RouterOSError("not-connected")
        encoded = [word.encode("utf-8") for word in (command, *words)]
        self.writer.write(b"".join(length_prefix(len(w)) + w for w in encoded) + b"\0")
        await self.writer.drain()
        rows = []
        total = 0
        error = None
        for _ in range(MAX_ROWS + 32):
            sentence = []
            for _ in range(128):
                raw = await read_word(self.reader)
                total += len(raw) + 5
                if total > MAX_REPLY:
                    raise RouterOSError("reply-too-large")
                if not raw:
                    break
                try:
                    sentence.append(raw.decode("utf-8"))
                except UnicodeDecodeError:
                    raise RouterOSError("invalid-encoding") from None
            else:
                raise RouterOSError("sentence-too-large")
            if not sentence:
                raise RouterOSError("empty-reply")
            fields = {}
            for word in sentence[1:]:
                if not word.startswith("=") or "=" not in word[1:]:
                    raise RouterOSError("invalid-reply")
                key, value = word[1:].split("=", 1)
                if key in fields:
                    raise RouterOSError("duplicate-field")
                fields[key] = value
            kind = sentence[0]
            if kind == "!done":
                if error:
                    raise RouterOSError(error)
                if command == "/login" and "ret" in fields:
                    raise RouterOSError("legacy-login-unsupported")
                return rows
            if kind == "!re":
                rows.append(fields)
                if len(rows) > MAX_ROWS:
                    raise RouterOSError("too-many-rows")
            elif kind in ("!trap", "!fatal"):
                # Classify privately; never put the untrusted server text in exceptions/logs.
                message = fields.get("message", "").lower()
                if command == "/login":
                    error = "authentication-failed"
                elif "permission" in message:
                    error = "permission-denied"
                elif "no such command" in message or "not supported" in message:
                    error = "endpoint-unavailable"
                else:
                    error = "request-rejected"
                if kind == "!fatal":
                    raise RouterOSError(error)
            elif kind != "!empty":  # RouterOS 7.18+ can emit !empty before !done.
                raise RouterOSError("unknown-reply")
        raise RouterOSError("too-many-sentences")
