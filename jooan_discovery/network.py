"""Cross-platform local-interface and directly connected RFC1918 detection."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable

import psutil

from .models import NetworkInfo

RFC1918 = tuple(
    ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
VIRTUAL_HINTS = (
    "docker",
    "hyper-v",
    "tailscale",
    "vbox",
    "virtualbox",
    "vmware",
    "vethernet",
    "wsl",
)


def is_rfc1918(address: str | ipaddress.IPv4Address) -> bool:
    ip = ipaddress.ip_address(address)
    return isinstance(ip, ipaddress.IPv4Address) and any(ip in block for block in RFC1918)


def network_is_rfc1918(network: ipaddress.IPv4Network) -> bool:
    return any(network.subnet_of(block) for block in RFC1918)


def _is_virtual(interface: str) -> bool:
    lowered = interface.lower()
    return any(hint in lowered for hint in VIRTUAL_HINTS)


def detect_networks(*, max_hosts: int = 1024, include_virtual: bool = False) -> list[NetworkInfo]:
    """Return every IPv4 interface with a documented scan selection decision."""
    results: list[NetworkInfo] = []
    stats = psutil.net_if_stats()
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            ip_text = address.address.split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(ip_text)
                network = ipaddress.ip_network(f"{ip_text}/{address.netmask}", strict=False)
            except ValueError:
                continue

            selected = True
            reason = "directly connected RFC1918 network"
            if not stats.get(interface) or not stats[interface].isup:
                selected, reason = False, "interface is down"
            elif ip.is_loopback:
                selected, reason = False, "loopback interface"
            elif ip.is_link_local:
                selected, reason = False, "IPv4 link-local address is not RFC1918"
            elif not network_is_rfc1918(network):
                selected, reason = False, "not an RFC1918 network"
            elif _is_virtual(interface) and not include_virtual:
                selected, reason = False, "virtual/tunnel interface excluded by default"
            elif max(network.num_addresses - 2, 0) > max_hosts:
                selected = False
                reason = f"network exceeds the {max_hosts}-host safety limit"

            results.append(
                NetworkInfo(
                    interface=interface,
                    address=str(ip),
                    network=str(network),
                    netmask=str(network.netmask),
                    broadcast=str(network.broadcast_address) if address.broadcast else None,
                    selected=selected,
                    reason=reason,
                )
            )
    return sorted(results, key=lambda item: (not item.selected, item.interface, item.address))


def validate_requested_networks(
    requested: Iterable[str], detected: Iterable[NetworkInfo]
) -> list[ipaddress.IPv4Network]:
    """Accept only RFC1918 networks contained by selected, directly connected networks."""
    direct = [ipaddress.ip_network(item.network) for item in detected if item.selected]
    validated: list[ipaddress.IPv4Network] = []
    for value in requested:
        try:
            candidate = ipaddress.ip_network(value, strict=True)
        except ValueError as err:
            raise ValueError(f"Invalid network {value!r}: {err}") from err
        if not isinstance(candidate, ipaddress.IPv4Network) or not network_is_rfc1918(candidate):
            raise ValueError(f"Refusing non-RFC1918 network: {candidate}")
        if not any(candidate.subnet_of(parent) for parent in direct):
            raise ValueError(f"Refusing network that is not directly connected: {candidate}")
        validated.append(candidate)
    return validated


def selected_networks(detected: Iterable[NetworkInfo]) -> list[ipaddress.IPv4Network]:
    return sorted(
        {ipaddress.ip_network(item.network) for item in detected if item.selected},
        key=lambda network: (int(network.network_address), network.prefixlen),
    )
