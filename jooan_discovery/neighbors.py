"""Read-only ARP/neighbor table collection."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
from collections.abc import Iterable

_MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


async def _command(*args: str) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await process.communicate()
        return stdout.decode(errors="replace")
    except FileNotFoundError, OSError:
        return ""


def parse_neighbor_output(output: str) -> dict[str, str]:
    neighbors: dict[str, str] = {}
    for line in output.splitlines():
        ip_match = _IP_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        try:
            ip = str(ipaddress.ip_address(ip_match.group()))
        except ValueError:
            continue
        mac = mac_match.group().replace("-", ":").upper()
        if mac not in {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}:
            neighbors[ip] = mac
    return neighbors


async def inspect_neighbors() -> dict[str, str]:
    system = platform.system()
    if system == "Windows":
        output = await _command("arp", "-a")
    elif system == "Linux":
        output = await _command("ip", "neigh", "show")
        if not output:
            output = await _command("arp", "-an")
    else:
        output = await _command("arp", "-an")
    return parse_neighbor_output(output)


def in_networks(address: str, networks: Iterable[ipaddress.IPv4Network]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)
