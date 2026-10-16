# MikroTik UniFi Switch Emulator — experimental M0–M5

The goal is a Docker service that makes RouterOS 7 switches visible in UniFi Network
through the **device-side inform protocol**, with observed ports, wired clients
and neighbor evidence. This revision implements synthetic milestones 0/1 and a
read-only RouterOS 7.24+ API collector with FDB/ARP/DHCP clients and observed neighbor
provenance and independent multi-device supervision for milestones 2–5. Adoption and Connected state have been observed
through an isolated UniFi Network 10.6.106 controller API.
The user confirmed live port activity, correct statistics and visible wired clients
from RB760iGS / RouterOS 7.24.4 in UniFi, and subsequently confirmed the M4 deployment
working, followed by a successful M5 deployment. M5 adds a separate CRS326 target
(192.168.0.251), a 26-port Switch Pro 24 profile and inventory CLI. An opt-in
UGW3 profile now exposes the RB WAN; actual gateway hardware and browser topology
remain to be verified.

| Capability | Status |
| --- | --- |
| TNBU framing, AES-CBC/GCM, zlib; independent crypto tests | Confirmed working locally |
| Persisted synthetic identity/key, safe diagnostic CLI, reconnect | Confirmed working with synthetic HTTP peer |
| Eight-port US8 candidate profile | Eight ports accepted by 10.6.106 controller API; UI rendering unverified |
| Configurable links, elapsed-time counters, hot reload | Confirmed locally and through 10.6.106 controller API |
| Synthetic wired clients and LLDP | Three wired clients and two LLDP records accepted by 10.6.106; topology UI unverified |
| Outbound adoption metadata exchange | Confirmed with 10.6.106: private key, GCM, provisioning and noop |
| UniFi Network 10.6.106 | Adoption/Connected observed through controller API; see [validation](docs/validation.md) |
| UniFi Network 8.0.24 / other releases | Adoption not yet tested |
| Read-only RouterOS 7.24+ API/API-SSL, six-port RB760iGS mapping | TCP/TLS fixtures tested; user confirmed local 7.24.4 probe after API source-IP correction |
| Observed FDB clients, VLAN scope, optional ARP/DHCP IP/name, aging | Implemented; wire fixtures and 10.6.106 controller API tested |
| RouterOS neighbor evidence and conservative LLDP topology export | Implemented; protocol/port uncertainty retained in diagnostics; 10.6.106 API tested |
| Independent devices, inventory CLI and separate CRS326 Compose service | Implemented; isolated processes/state/keys, eight- and 26-slot profiles |
| UGW3 gateway, configurable read-only WAN interface (default ether1) | [Gateway deployment](docs/gateway-wan.md); separate identity and WAN observations |
| RB5009 / mAP lite as UniFi switches: LLDP topology, LAG, PoE, real-MAC identity | [MikroTik RB5009 / mAP lite guide](docs/mikrotik-routeros-switches.md); map, LAG and PoE confirmed in UniFi OS Server 5.1.42 / Network 10.6.106 |
| VLAN / router configuration | Unsupported |
| Applying controller configuration to MikroTik | Unsupported by design |

**MikroTik RB5009 / mAP lite:** ready-made Compose files show both routers as UniFi
switches with ports, clients, topology map, LACP and PoE. `scripts/setup-mikrotik.sh`
asks only for the controller URL, router address and read-only API account; the device
MAC, ports, clients, neighbors and PoE are read from RouterOS. Site values stay in local
`.env` files that are never committed. See the [step-by-step guide](docs/mikrotik-routeros-switches.md),
including [what still needs manual input](docs/mikrotik-routeros-switches.md#what-is-automatic-and-what-is-not).

## Development quick start

Python 3.12+ and [uv](https://docs.astral.sh/uv/) are required. Run from the repository root:

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen --extra dev
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mtunifi sample
.venv/bin/mtunifi diagnose
```

The cache override is useful in the cloud environment where the home directory is
read-only; use a normal writable cache on your own machine. `sample` creates a private
local identity in ignored `.state/` and prints the synthetic payload without network
traffic. `diagnose` never prints adoption keys. `health` exits successfully only after
a recent valid inform response, with no subsequent error; it cannot prove adoption.

## Docker and adoption

For synthetic ports/traffic/client/LLDP scenarios, hot reload and upgrading an existing
adopted device, see [Milestone 1 telemetry](docs/synthetic-telemetry.md).
For the **RB760iGS at 192.168.0.249:8728**, read-only credentials, port mapping and
switching the existing lab to real observations, see [Milestone 2 RouterOS](docs/routeros.md).
For real wired clients, VLAN scoping, unknown IP, moves and aging, see
[Milestone 3 wired clients](docs/wired-clients.md). The same RouterOS Compose override
enables M3 and [M4 observed neighbors](docs/topology.md) after rebuilding, preserving
adoption and read-only credentials.
For the second CRS326 target, independent secrets/state and upgrade instructions,
see [M5 multi-device setup](docs/multi-device.md). The RB defaults to US8. To switch
it to UGW3 with configurable WAN collection and a new adoption volume, follow
[RB gateway/WAN setup](docs/gateway-wan.md). To retain both RB switch/client
telemetry and gateway WAN, use [simultaneous US8 + UGW3](docs/gateway-wan.md#run-us8-and-ugw3-together);
its separate services reuse the two existing identity volumes.
The lab Compose now selects the demo scenario by default and preserves adoption state.
If you deleted the device in UniFi and now see GCM `exchanging` with HTTP 400,
follow [re-adoption without changing MAC](docs/adoption.md#re-adopt-a-device-deleted-from-the-controller).

For a **complete local test environment using LinuxServer UniFi Network + authenticated
MongoDB**, use [deploy/lab](deploy/lab/README.md). It provides two separate Compose projects
sharing a dedicated network: controller/database first, simulator second. Database
passwords are generated locally and the simulator has its own persistent identity.
The commands below remain available for connecting the emulator to another controller.

```sh
cp .env.example .env  # preserve an existing .env
# Edit .env for your authorized isolated controller and emulator IP.
docker compose up -d --build
docker compose logs -f emulator
docker compose exec emulator mtunifi diagnose
```

The container runs as UID 10001, uses a persistent state volume, drops capabilities,
has a read-only root filesystem, bounded logs, a restart policy and health check.
It publishes no ports. Docker/Compose use the `.env` file; the Python CLI reads exported
environment variables, not dotenv files. Never put credentials in the inform URL.

In this cloud, build through the provided host trust bundle and a writable build cache:

```sh
export BUILDX_CONFIG=/workspace/.cache/buildx
docker compose -f docker-compose.yml -f compose.cloud.yml build
```

The optional override passes the host CA bundle as a build secret; TLS verification
stays enabled. Ordinary hosts with public trusted TLS do not need this override.
The [validation report](docs/validation.md) also documents the standalone build and
`scripts/docker-smoke.py`, which verifies the image against a synthetic HTTP peer.

Follow [the local adoption experiment](docs/adoption.md) for a disposable 8.0.24 controller,
wizard setup, UI verification, port/firewall rules and troubleshooting. Real-controller
tests are opt-in; the ordinary test suite never contacts UniFi or MikroTik equipment.

## Architecture and research

Configuration -> synthetic source or RouterOS API collector -> snapshot mapping ->
inform state machine -> TNBU codec -> controller.
Atomic per-device state stores identity and the controller-issued private key. The only
accepted provisioning effects are emulator metadata (key, encryption, cfgversion)
and a private-key `setdefault` reset of local adoption metadata.
Raw configuration and controller commands are safely ignored. No shell execution,
firmware download, RouterOS writes, external database or management web endpoint exists.

- [Protocol research and unresolved questions](docs/protocol-research.md)
- [Architecture and future integration boundaries](docs/architecture.md)
- [RouterOS deployment and diagnostics](docs/routeros.md)
- [Wired clients, VLAN correlation and aging](docs/wired-clients.md)
- [RouterOS mapping and remaining collection work](docs/routeros-mapping.md)
- [Limitations and security](docs/limitations.md)
- [Executed validation and compatibility evidence](docs/validation.md)

Synthetic mode needs no RouterOS credentials. RouterOS mode uses a dedicated read-only
API account and a mounted password file; MikroTik need not provide DHCP or routing.
API-SSL verifies certificates; the requested plaintext LAN API mode is explicit.

## Security and compatibility

Use a lab you control. Bootstrap encryption uses a public protocol constant and CBC
is unauthenticated. The state volume contains a private key in a mode-0600 file; protect
backups. Optional protocol tracing logs metadata only. Never reuse real device identities
or keys, modify production controller databases, or capture traffic without authorization.
The 10.6.106 result covers the synthetic UniFi profile. A successful actual MikroTik
API probe, live port activity/statistics and M3 wired clients are user-confirmed.
M4 and M5 deployment success are user-reported. Gateway hardware WAN collection,
detailed counter calibration and other controller releases remain unverified.

## Milestones

0. Demonstrate synthetic switch adoption and sustained Connected status, or document the blocker.
1. Determine accepted switch telemetry, configurable synthetic ports/clients/LLDP.
2. Implement read-only RouterOS collection and normalization with mocked API tests.
3. Add accurate FDB/ARP/DHCP/VLAN client correlation and aging.
4. Establish topology with explicit observation/inference provenance.
5. Add independent multi-device orchestration.

Milestones 0–5 have native fixtures and real controller API observations. The user
confirmed M2 ports/statistics, M3 clients and M4/M5 deployment. Gateway WAN
hardware behavior and browser topology rendering still require local validation.
License: MIT. Upstream protocol research and licensing notes are recorded in the research document.
