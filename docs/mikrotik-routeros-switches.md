# MikroTik RB5009 / mAP lite as UniFi switches

This guide runs two ready-made emulators that show RouterOS devices in UniFi Network
as native UniFi switches, including ports, wired clients, LLDP topology, LACP and PoE:

| Compose file | RouterOS device | Shown in UniFi as |
| --- | --- | --- |
| [compose.rb5009.yml](../compose.rb5009.yml) | RB5009 (ether1–8, sfp-sfpplus1) | USW Flex 2.5G 8 PoE (`USWED37`) |
| [compose.maplite.yml](../compose.maplite.yml) | mAP lite (ether1, pwr-line1, wlan1) | US 8 (`US8`, 3 slots) |

Everything is **read-only**: the emulator reads RouterOS over its API and never writes
to the router. Settings changed in the UniFi UI are ignored for these devices.

Tested with RouterOS 7.24.5 and UniFi Network 10.6.106 on UniFi OS Server 5.1.42.

## What is automatic and what is not

Read automatically from RouterOS, nothing to configure:

- port state, speed, duplex and counters; FDB clients with ARP/DHCP names;
  LLDP/MNDP/CDP neighbors; bond membership (shown as a UniFi LAG); PoE-out state,
  power, voltage and current per port; RouterOS identity (used as device name); the
  ISP gateway seen in ARP on the uplink port;
- the **device MAC** (`…_MAC=auto`, the default): the RouterOS ether1 MAC, read once
  when the identity is created;
- the **IP shown in UniFi**: defaults to the RouterOS address;
- the **port map**, if you set `…_MAP=auto`: RouterOS ports in order (ether, sfp, other
  Ethernet-type, wireless), ether1 as uplink.

Still needs you, because it cannot be discovered or would need write access:

| Item | Why it is manual | How |
| --- | --- | --- |
| Controller URL, router address, API user and password | The emulator must know where and how to connect before it can read anything | `scripts/setup-mikrotik.sh` asks for them |
| Read-only API user on RouterOS | Creating it needs admin rights; the emulator never writes to the router | [step 1](#1-read-only-api-user-on-routeros) |
| Adoption in UniFi | The controller requires an operator click | UniFi → Devices → Adopt |
| PoE budget (`MTUNIFI_RB5009_POE_BUDGET_W`) | RouterOS does not report the total PoE-out budget | Take it from the router's datasheet; without it "PoE in use" is not shown |
| Firmware version (`MTUNIFI_MAPLITE_VERSION`) | Only the controller knows its current firmware for the model | Copy `upgrade_to_firmware` from `scripts/unifi-topology.sh`; only to hide the update badge |
| Neighbor MAC rewrites (`…_NEIGHBOR_ALIASES`) | Needed only when a neighbor answers from a port MAC that differs from the MAC UniFi knows; this depends on the neighbor | Compare both sides in `scripts/unifi-topology.sh`, see [Topology notes](#topology-notes) |
| Port map for other MikroTik models | The ready-made maps place ports to match the UniFi faceplate (e.g. SFP+ on the combo slot, an assumed wlan speed) | Use `…_MAP=auto`, or copy and edit `examples/routeros-*.json` |
| Device names and port names in UniFi | Stored by the controller, not taken from the device | Rename in the UniFi UI |

## 1. Read-only API user on RouterOS

On each router, create a group with only `read` and `api` and a user limited to the
address of the host that runs Docker:

```
/user group add name=unifi-read policy=read,api
/user add name=unifi-reader group=unifi-read address=<docker-host-ip> password="<strong-password>"
/ip service set api address=<docker-host-ip> disabled=no
```

The account needs no `write`, `policy`, `sensitive`, `ssh` or `ftp` rights.

## 2. Clone and run the setup script

```bash
git clone -b moje https://github.com/joazif/unifi-simulator.git ~/docker/unifi-sim
cd ~/docker/unifi-sim
scripts/setup-mikrotik.sh rb5009
scripts/setup-mikrotik.sh maplite
```

The script asks for the controller inform URL, router address, API user and password,
writes `.env.<device>` (mode `600`, never committed) and `.secrets/<device>-password`,
then builds the image and probes the router read-only, listing the ports it found.
Optional values can be added to the `.env` file afterwards (see
[Settings](#settings) and `.env.*.example`).

## 3. Manual setup (alternative)

```bash
mkdir -p .secrets && chmod 700 .secrets
read -rsp "RB5009 API password: " P && echo && (umask 022; printf "%s" "$P" > .secrets/rb5009-password) && unset P
cp .env.rb5009.example .env.rb5009 && chmod 600 .env.rb5009
```

Fill in the three required values in `.env.rb5009`; leave the optional ones empty for
the automatic defaults. The container runs as UID 10001, so the password file must be
readable by others (`644`); the `700` directory keeps other local users out. A `600`
file fails with `password-file-invalid`.

The device MAC is the identity in UniFi. With `auto` it is read once at the first
start and kept in the state volume; set it explicitly only to reuse an existing
identity. A different MAC is a new device and needs a new adoption.

## 4. Check, probe and start

```bash
docker compose -f compose.rb5009.yml --env-file .env.rb5009 config --quiet
docker compose -f compose.rb5009.yml --env-file .env.rb5009 build
docker compose -f compose.rb5009.yml --env-file .env.rb5009 run --rm --no-deps rb5009 probe-routeros
docker compose -f compose.rb5009.yml --env-file .env.rb5009 up -d
```

Use the same commands with `compose.maplite.yml`, `.env.maplite` and `maplite`.
`probe-routeros` only reads the router and does not contact UniFi. Then adopt the
devices in UniFi (Devices → Adopt). HTTP 404 in the log before adoption is normal.

```bash
docker compose -f compose.rb5009.yml --env-file .env.rb5009 exec rb5009 mtunifi diagnose
```

should report `phase: exchanging` and `last_error: null` after adoption.

## Settings

Set in `.env.rb5009` / `.env.maplite` (the prefixes are `MTUNIFI_RB5009_*` and
`MTUNIFI_MAPLITE_*`):

| Variable | Meaning |
| --- | --- |
| `MTUNIFI_INFORM_URL` | Controller inform URL, e.g. `http://<controller>:8080/inform` |
| `…_HOST`, `…_USER` | RouterOS API address and read-only user (required) |
| `…_IP` | IPv4 shown for the device in UniFi; default: `…_HOST` |
| `…_MAC` | Device identity; default `auto` = RouterOS ether1 MAC |
| `…_MAP` | Port map file in the container, or `auto`; default: the bundled map for the model |
| `…_NEIGHBOR_ALIASES` | Optional `real=reported,...` neighbor MAC rewrites (see below) |
| `…_POLL_INTERVAL` | RouterOS read interval in seconds (RB5009 15, mAP lite 30) |
| `MTUNIFI_RB5009_POE_BUDGET_W` | Total PoE-out budget in W shown as "PoE in use" |
| `MTUNIFI_RB5009_MODEL` | UniFi model code, default `USWED37` |
| `MTUNIFI_MAPLITE_VERSION` | Firmware version to report (see update badge below) |
| `…_STATE_VOLUME` | Docker volume holding the identity and adoption key |

The compose files also enable these emulator options (general `MTUNIFI_*` settings):

| Option | Effect |
| --- | --- |
| `MTUNIFI_DEVICE_MAC` | Explicit device MAC, or `auto` to read the RouterOS ether1 MAC once |
| `MTUNIFI_ROUTEROS_MAP_FILE=auto` | Map RouterOS ports to slots automatically |
| `MTUNIFI_DEVICE_MODEL`, `MTUNIFI_DEVICE_VERSION` | Override the profile's model code / firmware version |
| `MTUNIFI_HOSTNAME_FROM_IDENTITY` | Report the RouterOS identity as hostname |
| `MTUNIFI_REPORT_UPLINK` | Send uplink `eth0` and `if_table` like real switches; without it the controller cannot build this device's uplink |
| `MTUNIFI_ROUTEROS_NEIGHBORS_RELAXED` | Also export MNDP/CDP and merged-protocol neighbors and LLDP seen on bond members; list direct neighbors in the port MAC tables |
| `MTUNIFI_ROUTEROS_NEIGHBOR_MAC_ALIASES` | Rewrite neighbor MACs (`real=reported`) |
| `MTUNIFI_ROUTEROS_UPLINK_FROM_ARP` | List the single ARP neighbor on the uplink port (ISP gateway) as parent |
| `MTUNIFI_ROUTEROS_UPLINK_LLDP_FROM_ARP` | Also add it as a derived (not received) LLDP neighbor |
| `MTUNIFI_REPORT_LAG` | Show RouterOS bonds as a UniFi LAG (display only) |
| `MTUNIFI_ROUTEROS_POE` | Read `/interface/ethernet/poe/monitor` (read-only) |
| `MTUNIFI_POE_BUDGET_W` | Device PoE budget; usage is summed from powered ports |

## Topology notes

- **Device MAC.** UniFi links devices by MAC. Real UniFi devices report the router by
  its LLDP chassis ID, which on RouterOS is the ether1 MAC; `…_MAC=auto` uses it.
- **Neighbor MAC rewrites.** Some neighbors answer from a port MAC that differs from
  the MAC UniFi knows them by (for example a UniFi switch port MAC ending one higher
  than the switch MAC, or the RB5009's ether5 MAC as seen by the mAP lite). Map them
  with `…_NEIGHBOR_ALIASES=<seen-mac>=<device-mac>`. `scripts/unifi-topology.sh`
  shows both sides.
- **Root of the map without a UniFi gateway.** If the router is bonded to a UniFi
  switch, the switch reports the router on a non-uplink member port, and the
  controller may hang the router under the switch. The ISP gateway from ARP on the
  router's uplink port (two options above) gives the router its own upstream.
- **Bonds.** RouterOS 7 reports bonding interfaces with type `bond`; they are shown
  as a LAG led by the lowest member port.

## PoE

The RB5009 is shown as `USWED37` (the PoE variant of USW Flex 2.5G 8). Per port the
emulator reports `poe_mode`, `poe_enable`/`poe_good`, `poe_power`, `poe_voltage` and
`poe_current` from RouterOS; RouterOS does not report the PD class, so it is
`Unknown`. A changed model code needs a new adoption to be stored by the controller.
Without the PoE model the controller warns that devices powered by the router have
"limited power availability".

## Firmware "Update available" badge

The controller offers an upgrade when the reported version differs from its current
firmware for that model. It cannot be hidden per device. To remove the badge, report
the controller's version, read from `upgrade_to_firmware` in
`scripts/unifi-topology.sh` output, e.g. `MTUNIFI_MAPLITE_VERSION=<that version>`.
The UI then shows that version instead of the RouterOS version. The emulator never
executes upgrade commands.

## Why not a gateway

`compose.rb5009-gateway.yml` shows the router as a gateway (UGW3/UGWXG with both WANs
and all ports). An adopted UniFi Security Gateway pins UniFi Network to version 10.6
(no later updates while it is adopted), so the switch view is the default.

## Diagnostics

| Script | Use |
| --- | --- |
| `scripts/unifi-topology.sh` | Logs in to your controller (credentials typed by you, not stored) and prints, read-only, each device's firmware, uplink, LLDP, downlinks, LAG and PoE fields. Set `UNIFI_URL=https://127.0.0.1:11443` on UniFi OS Server. |
| `scripts/neighbors.py`, `scripts/port_macs.py` | Pipe `mtunifi diagnose` output to see neighbors, export reasons, FDB counts and bonds |
| `scripts/poe_ports.py` | Pipe `probe-routeros` output to see PoE per port |
| `scripts/setup-mikrotik.sh` | Interactive first-time setup: `.env`, password file, build and read-only probe |

## Limitations

- Port names, device names and icons come from the controller and the model code;
  the emulator cannot rename ports. Rename them in the UI.
- Wireless and power-line slots on the mAP lite have no link monitor; `wlan1` uses an
  assumed speed (100 Mb/s, because UniFi greys out non-standard speeds).
- Nothing configured in UniFi is applied to RouterOS.
