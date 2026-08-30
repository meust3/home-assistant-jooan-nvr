"""Conservative SSDP, ONVIF WS-Discovery, and mDNS multicast probes."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
import struct
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from .models import NetworkInfo


async def _multicast_exchange(
    payloads: Iterable[bytes],
    destination: tuple[str, int],
    local_address: str,
    timeout: float,
) -> list[tuple[bytes, tuple[str, int]]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
    sock.bind((local_address, 0))
    loop = asyncio.get_running_loop()
    replies: list[tuple[bytes, tuple[str, int]]] = []
    try:
        for payload in payloads:
            await loop.sock_sendto(sock, payload, destination)
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), remaining)
            except TimeoutError:
                break
            replies.append(item)
    finally:
        sock.close()
    return replies


def _selected_interfaces(networks: Iterable[NetworkInfo]) -> list[NetworkInfo]:
    return [item for item in networks if item.selected]


def _parse_http_headers(payload: bytes) -> dict[str, str]:
    text = payload.decode("iso-8859-1", errors="replace")
    headers: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n")[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


async def discover_ssdp(
    networks: Iterable[NetworkInfo], timeout: float = 2.0
) -> list[dict[str, str]]:
    request = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )
    tasks = [
        _multicast_exchange([request], ("239.255.255.250", 1900), item.address, timeout)
        for item in _selected_interfaces(networks)
    ]
    results: list[dict[str, str]] = []
    if not tasks:
        return results
    for interface, replies in zip(
        _selected_interfaces(networks),
        await asyncio.gather(*tasks, return_exceptions=True),
        strict=True,
    ):
        if isinstance(replies, BaseException):
            continue
        for payload, source in replies:
            headers = _parse_http_headers(payload)
            headers.update({"source": source[0], "interface": interface.interface})
            results.append(headers)
    unique = {(item.get("source"), item.get("location"), item.get("st")): item for item in results}
    return list(unique.values())


def _ws_probe(types: str) -> bytes:
    message_id = uuid.uuid4()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
 <e:Header>
  <w:MessageID>uuid:{message_id}</w:MessageID>
  <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body><d:Probe><d:Types>{types}</d:Types></d:Probe></e:Body>
</e:Envelope>""".encode()


def _xml_texts(payload: bytes, local_name: str) -> list[str]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return []
    return [
        node.text.strip()
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == local_name and node.text
    ]


async def discover_onvif(
    networks: Iterable[NetworkInfo], timeout: float = 3.0
) -> list[dict[str, Any]]:
    probes = [_ws_probe("dn:NetworkVideoTransmitter"), _ws_probe("")]
    selected = _selected_interfaces(networks)
    tasks = [
        _multicast_exchange(probes, ("239.255.255.250", 3702), item.address, timeout)
        for item in selected
    ]
    results: list[dict[str, Any]] = []
    if not tasks:
        return results
    for interface, replies in zip(
        selected, await asyncio.gather(*tasks, return_exceptions=True), strict=True
    ):
        if isinstance(replies, BaseException):
            continue
        for payload, source in replies:
            xaddrs = [url for text in _xml_texts(payload, "XAddrs") for url in text.split()]
            scopes = [scope for text in _xml_texts(payload, "Scopes") for scope in text.split()]
            types = [item for text in _xml_texts(payload, "Types") for item in text.split()]
            addresses = _xml_texts(payload, "Address")
            identity = " ".join([*xaddrs, *scopes, *types]).lower()
            if "onvif" not in identity and "networkvideotransmitter" not in identity:
                # The empty Probe also elicits Windows WSD printers/computers.
                # Do not call those devices ONVIF.
                continue
            results.append(
                {
                    "source": source[0],
                    "interface": interface.interface,
                    "xaddrs": xaddrs,
                    "scopes": scopes,
                    "types": types,
                    "endpoint_references": addresses,
                }
            )
    unique = {(item["source"], tuple(item["xaddrs"])): item for item in results}
    return list(unique.values())


def _dns_name(name: str) -> bytes:
    return (
        b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split("."))
        + b"\0"
    )


def _dns_query(name: str, query_type: int = 12) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    # The unicast-response bit makes replies arrive on our safe ephemeral source port.
    return header + _dns_name(name) + struct.pack("!HH", query_type, 0x8001)


def _read_dns_name(payload: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        raise ValueError("DNS compression pointer loop")
    labels: list[str] = []
    original_end: int | None = None
    while offset < len(payload):
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            suffix, _ = _read_dns_name(payload, pointer, depth + 1)
            labels.append(suffix)
            original_end = original_end or offset + 2
            break
        offset += 1
        if length == 0:
            original_end = original_end or offset
            break
        if offset + length > len(payload):
            raise ValueError("truncated DNS label")
        labels.append(payload[offset : offset + length].decode(errors="replace"))
        offset += length
    return ".".join(part for part in labels if part), original_end or offset


def parse_mdns_packet(payload: bytes, source: str) -> list[dict[str, Any]]:
    if len(payload) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    offset = 12
    try:
        for _ in range(qd):
            _, offset = _read_dns_name(payload, offset)
            offset += 4
        records: list[dict[str, Any]] = []
        for _ in range(an + ns + ar):
            name, offset = _read_dns_name(payload, offset)
            rr_type, rr_class, ttl, length = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10
            end = offset + length
            if end > len(payload):
                break
            value: Any
            if rr_type in {5, 12}:
                value, _ = _read_dns_name(payload, offset)
            elif rr_type == 33 and length >= 6:
                priority, weight, port = struct.unpack("!HHH", payload[offset : offset + 6])
                target, _ = _read_dns_name(payload, offset + 6)
                value = {"priority": priority, "weight": weight, "port": port, "target": target}
            elif rr_type == 16:
                chunks: list[str] = []
                cursor = offset
                while cursor < end:
                    chunk_length = payload[cursor]
                    cursor += 1
                    chunks.append(payload[cursor : cursor + chunk_length].decode(errors="replace"))
                    cursor += chunk_length
                value = chunks
            elif rr_type == 1 and length == 4:
                value = socket.inet_ntoa(payload[offset:end])
            elif rr_type == 28 and length == 16:
                value = str(ipaddress.ip_address(payload[offset:end]))
            else:
                value = base64.b64encode(payload[offset:end]).decode()
            records.append(
                {
                    "source": source,
                    "name": name,
                    "type": rr_type,
                    "class": rr_class,
                    "ttl": ttl,
                    "value": value,
                }
            )
            offset = end
        return records
    except ValueError, struct.error:
        return []


async def discover_mdns(
    networks: Iterable[NetworkInfo], timeout: float = 2.5
) -> list[dict[str, Any]]:
    names = (
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_https._tcp.local",
        "_rtsp._tcp.local",
        "_onvif._tcp.local",
    )
    payloads = [_dns_query(name) for name in names]
    selected = _selected_interfaces(networks)
    tasks = [
        _multicast_exchange(payloads, ("224.0.0.251", 5353), item.address, timeout)
        for item in selected
    ]
    records: list[dict[str, Any]] = []
    if not tasks:
        return records
    for replies in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(replies, BaseException):
            continue
        for payload, source in replies:
            records.extend(parse_mdns_packet(payload, source[0]))
    unique = {
        (item["source"], item["name"], item["type"], repr(item["value"])): item for item in records
    }
    return list(unique.values())


def source_from_location(location: str) -> str | None:
    try:
        return urlsplit(location).hostname
    except ValueError:
        return None
