import json
import time
from types import SimpleNamespace

import httpx
import pytest

from mtunifi.emulator import Emulator
from mtunifi.protocol import BOOTSTRAP_KEY, decode, encode
from mtunifi.routeros import RouterOSSource
from mtunifi.routeros_api import RouterOSError
from mtunifi.storage import Store

KEY = bytes.fromhex("12" * 16)


@pytest.mark.parametrize("tls", [False, True])
async def test_gateway_native_api_gcm_wan_loss_restore_counter_reset_and_optional_ip(
    routeros_peer, tmp_path, monkeypatch, tls
):
    peer = await routeros_peer(tls=tls)
    settings = peer.settings(profile="ugw3-experimental", routeros_poll_interval=5)
    settings.routeros_map_file = None
    store = Store(tmp_path / "gateway")
    with store.lock():
        state = store.load_or_create()
    tick = [100]
    monkeypatch.setattr(
        "mtunifi.emulator.time", SimpleNamespace(monotonic=lambda: tick[0], time=time.time)
    )
    app, packets = Emulator(settings, store, state), []

    def controller(request):
        key = KEY if packets else BOOTSTRAP_KEY
        packet = decode(request.content, key)
        packets.append(packet)
        body = (
            {"_type": "noop"}
            if len(packets) > 1
            else {"_type": "setparam", "mgmt_cfg": f"authkey={KEY.hex()}\nuse_aes_gcm=1"}
        )
        return httpx.Response(
            200, stream=httpx.ByteStream(encode(body, packet.mac, key, mode=packet.mode))
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(controller)) as client:
        assert await app.exchange(client)
        assert packets[-1].body["model"] == "UGW3"
        (wan,) = packets[-1].body["if_table"]
        assert wan["name"] == "eth0" and wan["mac"] == state.mac
        assert wan["rx_bytes"] == peer.rx + 1 and wan["tx_bytes"] == 1001
        assert wan["ip"] == "198.51.100.2" and wan["netmask"] == "255.255.255.0"
        assert wan["up"] and wan["speed"] == 1000
        assert "port_table" not in packets[-1].body
        tick[0] = 106
        peer.traps["/ip/address/print"] = "not enough permissions: PRIVATE"
        assert await app.exchange(client)
        (wan,) = packets[-1].body["if_table"]
        assert "ip" not in wan and wan["rx_bytes"] == peer.rx + 1
        summary = store.load_telemetry()
        assert summary["status"] == "degraded" and "PRIVATE" not in json.dumps(summary)
        peer.traps.clear()
        peer.monitors["*1"] = [{"status": "no-link"}]
        tick[0] = 112
        assert await app.exchange(client)
        assert packets[-1].body["if_table"][0]["up"] is False
        peer.monitors["*1"] = [{"status": "link-ok", "rate": "100Mbps", "full-duplex": "yes"}]
        peer.rx, peer.uptime, tick[0] = 10, "2s", 118
        assert await app.exchange(client)
        assert packets[-1].body["if_table"][0]["speed"] == 100
        assert packets[-1].body["uptime"] == 2
        assert "counters:reset" in store.load_telemetry()["observations"]["warnings"]
        peer.drop, tick[0] = "/ip/address/print", 124
        count = len(packets)
        assert not await app.exchange(client) and len(packets) == count
        assert store.load().authkey.get_secret_value() == KEY.hex()
        peer.drop, tick[0] = None, 140
        assert await app.exchange(client)
    assert all(p.mode == "gcm" for p in packets[1:])
    assert len({p.mac for p in packets}) == 1 and state.phase == "exchanging"
    paths = {c[0] for c in peer.commands}
    assert "/ip/address/print" in paths and "/interface/bridge/host/print" not in paths
    assert paths <= {
        "/login",
        "/system/resource/print",
        "/system/identity/print",
        "/interface/print",
        "/interface/ethernet/print",
        "/interface/ethernet/monitor",
        "/ip/address/print",
    }


@pytest.mark.parametrize("kind,name", [("vlan", "wan-vlan"), ("pppoe-out", "pppoe-out1")])
async def test_virtual_wan_only_uses_selected_interface_counters_not_parent(
    routeros_peer, monkeypatch, kind, name
):
    peer = await routeros_peer()
    original = peer.tables

    def tables():
        result = original()
        result["/interface/print"].append(
            {
                "name": name,
                "type": kind,
                "disabled": "false",
                "running": "true",
                "rx-byte": "123456",
                "tx-byte": "5678",
            }
        )
        result["/ip/address/print"].append({"interface": name, "address": "203.0.113.9/32"})
        return result

    monkeypatch.setattr(peer, "tables", tables)
    source = RouterOSSource(peer.settings(profile="ugw3-experimental", routeros_wan_interface=name))
    body = await source.collect(100, "02:00:00:00:00:99")
    (wan,) = body["if_table"]
    assert body["uplink"] == "eth0" and wan["name"] == "eth0"
    assert source.last_summary["observations"]["wan"]["interface"] == name
    assert (wan["rx_bytes"], wan["tx_bytes"]) == (123456, 5678)
    assert wan["ip"] == "203.0.113.9" and wan["netmask"] == "255.255.255.255"
    assert "speed" not in wan and "full_duplex" not in wan
    assert not any(c[0] == "/interface/ethernet/monitor" for c in peer.commands)


async def test_missing_or_malformed_wan_data_does_not_send_fabricated_counters(
    routeros_peer, monkeypatch
):
    peer = await routeros_peer()
    source = RouterOSSource(
        peer.settings(profile="ugw3-experimental", routeros_wan_interface="absent")
    )
    with pytest.raises(RouterOSError, match="wan-interface-missing"):
        await source.collect(100, "02:00:00:00:00:99")
    original = peer.tables

    def tables():
        result = original()
        next(r for r in result["/interface/print"] if r.get("name") == "ether1").pop("rx-byte")
        return result

    monkeypatch.setattr(peer, "tables", tables)
    source = RouterOSSource(peer.settings(profile="ugw3-experimental"))
    with pytest.raises(RouterOSError, match="required-wan-data-missing"):
        await source.collect(100, "02:00:00:00:00:99")
    assert source.last_summary["status"] == "unavailable"


async def test_gateway_with_matching_port_map_reports_ports_and_two_wans(routeros_peer):
    peer = await routeros_peer()
    mapping = peer.directory / "gateway-map.json"
    mapping.write_text(
        json.dumps(
            {
                "profile": "rb5009-gateway-experimental",
                "ports": [
                    {"port_idx": 1, "interface": "ether1", "is_uplink": True},
                    {"port_idx": 2, "interface": "ether2"},
                    {"port_idx": 9, "interface": "sfp1"},
                ],
            }
        )
    )
    settings = peer.settings(
        profile="rb5009-gateway-experimental",
        routeros_wan_interface="ether1",
        routeros_wan2_interface="ether2",
        device_model="UXGPRO",
    ).model_copy(update={"routeros_map_file": mapping})
    body = await RouterOSSource(settings).collect(1, "02:00:00:00:00:10")
    assert [p["port_idx"] for p in body["port_table"]] == list(range(1, 10))
    assert body["port_table"][0]["up"] and not body["port_table"][8]["up"]
    assert [i["name"] for i in body["if_table"]] == ["eth0", "eth2"]
    assert [c["name"] for c in body["config_port_table"]] == ["wan", "wan2"]
    assert settings.model_code == "UXGPRO"


async def test_gateway_ifname_map_exports_every_port_in_if_table(routeros_peer):
    peer = await routeros_peer()
    mapping = peer.directory / "ifname-map.json"
    mapping.write_text(
        json.dumps(
            {
                "profile": "rb5009-gateway-experimental",
                "ports": [
                    {"port_idx": 1, "interface": "ether1", "ifname": "eth8"},
                    {"port_idx": 2, "interface": "ether2", "ifname": "eth0"},
                    {"port_idx": 3, "interface": "ether3", "ifname": "eth1"},
                    {"port_idx": 9, "interface": "sfp1", "ifname": "eth2"},
                ],
            }
        )
    )
    settings = peer.settings(
        profile="rb5009-gateway-experimental",
        routeros_wan_interface="ether1",
        routeros_wan2_interface="ether2",
    ).model_copy(update={"routeros_map_file": mapping})
    body = await RouterOSSource(settings).collect(1, "02:00:00:00:00:10")
    assert "port_table" not in body and body["uplink"] == "eth8"
    assert [i["name"] for i in body["if_table"]] == ["eth0", "eth1", "eth2", "eth8"]
    assert body["config_port_table"] == [
        {"ifname": "eth0", "name": "wan2", "type": "wan"},
        {"ifname": "eth1", "name": "lan", "type": "lan"},
        {"ifname": "eth2", "name": "lan2", "type": "lan"},
        {"ifname": "eth8", "name": "wan", "type": "wan"},
    ]
    eth8 = body["if_table"][3]
    assert eth8["up"] and eth8["mac"] == "02:00:00:00:00:18"
    assert settings.model_code == "UGWXG"
