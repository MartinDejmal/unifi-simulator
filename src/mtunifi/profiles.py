"""Explicit device profiles; a device's class is never inferred from its address."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    name: str
    model: str
    display: str
    version: str
    required_version: str
    max_speeds: tuple[int, ...]
    kind: str = "switch"

    @property
    def port_count(self) -> int:
        return len(self.max_speeds)


PROFILES = {
    "us8-experimental": DeviceProfile(
        "us8-experimental", "US8", "UniFi Switch 8", "4.3.28.11361", "5.4.0", (1000,) * 8
    ),
    # mAP lite: ether1 (100M), pwr-line1 (internal) and wlan1 (2.4 GHz); the model code stays US8.
    "maplite-experimental": DeviceProfile(
        "maplite-experimental",
        "US8",
        "UniFi Switch 8",
        "7.24.5.0",  # mirrors the RouterOS version shown in UniFi; update when RouterOS changes
        "5.4.0",
        (100, 100, 300),
    ),
    # RB5009 as a gateway that reports all its ports. UGWXG (USG XG 8) has exactly nine
    # interfaces eth0-eth8 in the controller's uidb; each mapped slot names its ifname.
    # Override the model code with MTUNIFI_DEVICE_MODEL.
    "rb5009-gateway-experimental": DeviceProfile(
        "rb5009-gateway-experimental",
        "UGWXG",
        "UniFi Security Gateway XG 8",
        "7.24.5.0",
        "5.4.0",
        (2500,) + (1000,) * 7 + (10000,),
        "gateway",
    ),
    # RB5009 as a switch: USW Flex 2.5G 8 has ports 1-8 (2.5G) and a 9/10 RJ45/SFP+ combo.
    # A switch view keeps UniFi Network updatable (an adopted USG pins it to 10.6).
    "rb5009-switch-experimental": DeviceProfile(
        "rb5009-switch-experimental",
        "USWED36",
        "UniFi Switch Flex 2.5G 8",
        "7.24.5.0",
        "5.4.0",
        (2500,) * 8 + (10000, 10000),
    ),
    "usw-pro24-experimental": DeviceProfile(
        "usw-pro24-experimental",
        "US24PRO2",
        "UniFi Switch Pro 24",
        "6.6.61.15153",
        "5.13.10",
        (1000,) * 24 + (10000,) * 2,
    ),
    "ugw3-experimental": DeviceProfile(
        "ugw3-experimental",
        "UGW3",
        "UniFi Security Gateway",
        "4.4.57.5578372",
        "5.4.0",
        (),
        "gateway",
    ),
}


def profile(name: str) -> DeviceProfile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError("Unsupported device profile") from None
