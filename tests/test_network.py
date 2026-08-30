from __future__ import annotations

import ipaddress
import socket
from types import SimpleNamespace

import pytest

from jooan_discovery.models import NetworkInfo
from jooan_discovery.network import detect_networks, validate_requested_networks
from jooan_discovery.scanner import _is_isolated_wireless_camera


def _address(address: str, netmask: str, broadcast: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        family=socket.AF_INET,
        address=address,
        netmask=netmask,
        broadcast=broadcast,
    )


def test_detect_networks_selects_only_physical_rfc1918(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "jooan_discovery.network.psutil.net_if_addrs",
        lambda: {
            "Wi-Fi": [_address("192.168.77.148", "255.255.255.0", "192.168.77.255")],
            "vEthernet (Default Switch)": [
                _address("172.31.240.1", "255.255.240.0", "172.31.255.255")
            ],
            "Tailscale": [_address("100.64.0.10", "255.255.255.255")],
            "Ethernet": [_address("169.254.1.2", "255.255.0.0")],
        },
    )
    monkeypatch.setattr(
        "jooan_discovery.network.psutil.net_if_stats",
        lambda: {
            name: SimpleNamespace(isup=True)
            for name in ("Wi-Fi", "vEthernet (Default Switch)", "Tailscale", "Ethernet")
        },
    )

    detected = detect_networks()

    assert [item.network for item in detected if item.selected] == ["192.168.77.0/24"]
    reasons = {item.interface: item.reason for item in detected}
    assert "virtual/tunnel" in reasons["vEthernet (Default Switch)"]
    assert "not an RFC1918" in reasons["Tailscale"]
    assert "link-local" in reasons["Ethernet"]


def test_requested_network_must_be_private_and_direct() -> None:
    detected = [
        NetworkInfo(
            interface="Wi-Fi",
            address="192.168.77.148",
            network="192.168.77.0/24",
            netmask="255.255.255.0",
            broadcast="192.168.77.255",
            selected=True,
            reason="directly connected RFC1918 network",
        )
    ]
    assert str(validate_requested_networks(["192.168.77.0/25"], detected)[0]) == "192.168.77.0/25"
    with pytest.raises(ValueError, match="non-RFC1918"):
        validate_requested_networks(["8.8.8.0/24"], detected)
    with pytest.raises(ValueError, match="not directly connected"):
        validate_requested_networks(["192.168.78.0/24"], detected)


def test_isolated_wireless_topology_does_not_depend_on_a_real_subnet() -> None:
    lan = [ipaddress.ip_network("192.168.77.0/24")]

    assert _is_isolated_wireless_camera({"InterfaceType": "Wireless", "IPAddr": "10.99.0.2"}, lan)
    assert not _is_isolated_wireless_camera(
        {"InterfaceType": "Wireless", "IPAddr": "192.168.77.20"}, lan
    )
    assert not _is_isolated_wireless_camera(
        {"InterfaceType": "Ethernet", "IPAddr": "10.99.0.2"}, lan
    )
