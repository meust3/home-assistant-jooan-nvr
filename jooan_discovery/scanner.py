"""Progressive discovery orchestration."""

from __future__ import annotations

import asyncio
import getpass
import ipaddress
import logging
import shutil
import sys
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import __version__
from .fingerprint import merits_deep_probe, score_host
from .kp2p import validate_kp2p_streams
from .models import HostRecord, OnvifEvidence, ScanResult, ServiceEvidence
from .multicast import discover_mdns, discover_onvif, discover_ssdp, source_from_location
from .neighbors import in_networks, inspect_neighbors
from .netsdk import investigate_netsdk
from .network import detect_networks, selected_networks, validate_requested_networks
from .onvif import investigate_onvif
from .oui import has_oui_database, lookup_vendor
from .probes import (
    DEFAULT_PORTS,
    describe_rtsp_path,
    eseecloud_paths,
    fetch_upnp_description,
    ping_hosts,
    probe_http_services,
    probe_rtsp_service,
    probe_websocket,
    reverse_hostname,
    scan_tcp_ports,
)
from .report import write_reports
from .security import Credentials

LOGGER = logging.getLogger(__name__)
Progress = Callable[[str], None]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _addresses(networks: Iterable[ipaddress.IPv4Network]) -> list[str]:
    return [str(address) for network in networks for address in network.hosts()]


def _address_allowed(address: str | None, networks: Iterable[ipaddress.IPv4Network]) -> bool:
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)


def _is_isolated_wireless_camera(
    camera: dict[str, object], lan_networks: Iterable[ipaddress.IPv4Network]
) -> bool:
    """Return whether metadata places a wireless camera off the selected LANs."""
    if str(camera.get("InterfaceType", "")).lower() != "wireless":
        return False
    try:
        address = ipaddress.ip_address(str(camera.get("IPAddr", "")))
    except ValueError:
        return False
    return (
        isinstance(address, ipaddress.IPv4Address)
        and address.is_private
        and not address.is_unspecified
        and not address.is_loopback
        and not any(address in network for network in lan_networks)
    )


def _host_for(hosts: dict[str, HostRecord], address: str) -> HostRecord:
    return hosts.setdefault(address, HostRecord(address=address))


def _plausible_onvif_endpoints(host: HostRecord) -> list[str]:
    endpoints: list[str] = []
    for item in host.onvif:
        if item.endpoint not in endpoints:
            endpoints.append(item.endpoint)
    # Guesses are limited to open web-like ports on a device that already passed the candidate gate.
    for port in host.open_ports:
        if port in {80, 8000, 8080, 8081, 8899}:
            endpoint = f"http://{host.address}:{port}/onvif/device_service"
            if endpoint not in endpoints:
                endpoints.append(endpoint)
    return endpoints[:6]


def _rtsp_ports(host: HostRecord) -> list[int]:
    ports = {item.port for item in host.rtsp if item.confirmed}
    if 554 in host.open_ports:
        ports.add(554)
    if ports and 80 in host.open_ports:
        ports.add(80)
    for item in host.onvif:
        for stream in item.stream_uris:
            try:
                parsed = urlsplit(stream["uri"])
                if parsed.port:
                    ports.add(parsed.port)
                elif parsed.scheme == "rtsp":
                    ports.add(554)
            except KeyError, ValueError:
                continue
    return sorted(ports)


def _online_channels(host: HostRecord) -> list[int]:
    if not host.local_api:
        return []
    status = host.local_api[0].results.get("ipc_status")
    if not isinstance(status, list):
        return []
    online: list[int] = []
    for item in status:
        if not isinstance(item, dict):
            continue
        state = str(item.get("Status", "")).lower()
        flag = str(item.get("BcamOnline", "")).lower()
        if state == "connect success" or flag == "true":
            try:
                online.append(int(item["ID"]))
            except KeyError, TypeError, ValueError:
                continue
    return sorted(set(online))


async def _get_credentials(username: str | None) -> Credentials | None:
    if not sys.stdin.isatty():
        return None
    entered_username = username or await asyncio.to_thread(input, "NVR username: ")
    password = await asyncio.to_thread(getpass.getpass, "NVR password (not echoed): ")
    return Credentials(entered_username, password)


async def _investigate_candidate(
    host: HostRecord,
    *,
    credentials: Credentials | None,
    test_events: bool,
    timeout: float,
) -> None:
    indicators = {indicator for item in host.http for indicator in item.indicators}
    if "Netsdk local API" in indicators:
        host.local_api = [
            await investigate_netsdk(
                host.address,
                80,
                credentials=credentials,
                timeout=timeout,
            )
        ]
    if "KP2P local web module" in indicators and not any(
        item.port == 10000 for item in host.services
    ):
        websocket, banner = await probe_websocket(host.address, 10000, timeout=timeout)
        if websocket:
            host.services.append(
                ServiceEvidence(
                    port=10000,
                    protocol="kp2p-websocket",
                    banner=banner,
                )
            )
            host.services.sort(key=lambda item: item.port)
            if credentials and host.local_api and host.local_api[0].authenticated:
                online = _online_channels(host)
                if online:
                    host.kp2p = [
                        await validate_kp2p_streams(
                            host.address,
                            10000,
                            credentials,
                            online,
                            timeout=max(timeout, 5.0),
                        )
                    ]

    prior_onvif = {item.endpoint: item for item in host.onvif}
    investigated: list[OnvifEvidence] = []
    for endpoint in _plausible_onvif_endpoints(host):
        method = (
            prior_onvif.get(endpoint).discovered_by
            if endpoint in prior_onvif
            else "targeted path probe"
        )
        evidence = await investigate_onvif(
            endpoint,
            credentials=credentials,
            discovered_by=method,
            test_events=test_events,
            timeout=timeout,
        )
        investigated.append(evidence)
        if evidence.reachable:
            # GetCapabilities provides the authoritative service URLs; do not keep guessing ports.
            break
        if evidence.auth_required:
            break
    if investigated:
        host.onvif = investigated

    # ONVIF stream URIs are authoritative and are tested before ecosystem path hypotheses.
    tested: set[tuple[int, str]] = set()
    for onvif in host.onvif:
        for stream in onvif.stream_uris:
            uri = stream.get("uri", "")
            try:
                parsed = urlsplit(uri)
            except ValueError:
                continue
            port = parsed.port or 554
            path = parsed.path.lstrip("/")
            if not path or (port, path) in tested:
                continue
            tested.add((port, path))
            item = await describe_rtsp_path(
                host.address,
                port,
                path,
                credentials=credentials,
                stream="onvif",
                timeout=timeout,
            )
            host.rtsp.append(item)

    for port in _rtsp_ports(host):
        if not any(item.port == port and item.path == "/" and item.confirmed for item in host.rtsp):
            service = await probe_rtsp_service(
                host.address, port, credentials=credentials, timeout=timeout
            )
            host.rtsp.append(service)
        if not any(item.port == port and item.path == "/" and item.confirmed for item in host.rtsp):
            continue

        first_paths = eseecloud_paths(1)
        first_results = await asyncio.gather(
            *(
                describe_rtsp_path(
                    host.address,
                    port,
                    path,
                    credentials=credentials,
                    channel=channel,
                    stream=stream,
                    timeout=timeout,
                )
                for path, channel, stream in first_paths
                if (port, path) not in tested
            )
        )
        host.rtsp.extend(first_results)
        tested.update((port, path) for path, _, _ in first_paths)

        # A 401 without credentials proves authentication, but not path validity.
        # Avoid 14 redundant requests in that case.
        auth_blocked = (
            bool(first_results)
            and all(item.status == 401 for item in first_results)
            and not credentials
        )
        if not auth_blocked:
            remaining = eseecloud_paths(8)[2:]
            remaining_results = await asyncio.gather(
                *(
                    describe_rtsp_path(
                        host.address,
                        port,
                        path,
                        credentials=credentials,
                        channel=channel,
                        stream=stream,
                        timeout=timeout,
                    )
                    for path, channel, stream in remaining
                    if (port, path) not in tested
                )
            )
            host.rtsp.extend(remaining_results)
            tested.update((port, path) for path, _, _ in remaining)

        known_worked = any(
            item.confirmed and item.port == port and item.path != "/" for item in host.rtsp
        )
        if not known_worked and not auth_blocked:
            alternatives = [("onvif1", None, "main"), ("onvif2", None, "sub")]
            alternative_results = await asyncio.gather(
                *(
                    describe_rtsp_path(
                        host.address,
                        port,
                        path,
                        credentials=credentials,
                        channel=channel,
                        stream=stream,
                        timeout=timeout,
                    )
                    for path, channel, stream in alternatives
                )
            )
            host.rtsp.extend(alternative_results)
            known_worked = any(item.confirmed for item in alternative_results)

        # The credential-in-path legacy pattern is last resort and is never emitted unredacted.
        if not known_worked and credentials:
            legacy_results = []
            for channel in range(1, 9):
                path = (
                    f"user={quote(credentials.username, safe='')}_password="
                    f"{quote(credentials.password, safe='')}_channel={channel}_stream=0.sdp"
                )
                legacy_results.append(
                    await describe_rtsp_path(
                        host.address,
                        port,
                        path,
                        credentials=credentials,
                        channel=channel - 1,
                        stream="main",
                        timeout=timeout,
                    )
                )
            host.rtsp.extend(legacy_results)


async def run_scan(
    *,
    artifacts: Path,
    requested_networks: list[str] | None = None,
    include_virtual: bool = False,
    max_hosts: int = 1024,
    ports: Iterable[int] = DEFAULT_PORTS,
    connect_timeout: float = 0.45,
    protocol_timeout: float = 2.5,
    concurrency: int = 128,
    username: str | None = None,
    prompt_credentials: bool = False,
    test_events: bool = False,
    progress: Progress | None = None,
) -> ScanResult:
    say = progress or (lambda message: LOGGER.info(message))
    ports = tuple(ports)
    result = ScanResult(schema_version=1, scanner_version=__version__, started_at=_now())
    result.optional_tools = {
        "nmap": shutil.which("nmap") is not None,
        "ffprobe": shutil.which("ffprobe") is not None,
        "offline_oui_database": has_oui_database(),
    }

    say("Detecting local RFC1918 interfaces")
    result.networks = detect_networks(max_hosts=max_hosts, include_virtual=include_virtual)
    if requested_networks:
        networks = validate_requested_networks(requested_networks, result.networks)
    else:
        networks = selected_networks(result.networks)
    if not networks:
        result.warnings.append("No safe directly connected RFC1918 network was selected.")
        result.completed_at = _now()
        write_reports(result, artifacts)
        return result
    address_list = _addresses(networks)
    allowed_addresses = set(address_list)
    say("Inspecting existing ARP/neighbor state (passive)")
    initial_neighbors = {
        address: mac
        for address, mac in (await inspect_neighbors()).items()
        if in_networks(address, networks)
    }

    say("Sending limited SSDP, mDNS, and ONVIF WS-Discovery multicast probes")
    ssdp, mdns, ws_discovery = await asyncio.gather(
        discover_ssdp(result.networks, protocol_timeout),
        discover_mdns(result.networks, protocol_timeout),
        discover_onvif(result.networks, protocol_timeout),
    )
    for item in ssdp:
        location = item.get("location")
        source = item.get("source") or source_from_location(location or "")
        if location and _address_allowed(source, networks):
            item.update(
                await fetch_upnp_description(
                    location, allowed_addresses=allowed_addresses, timeout=protocol_timeout
                )
            )
    result.protocol_discovery = {"ssdp": ssdp, "mdns": mdns, "onvif_ws_discovery": ws_discovery}

    say(f"Rate-limited ICMP and {len(ports)}-port TCP scan of {len(address_list)} LAN hosts")
    responsive, open_services = await asyncio.gather(
        ping_hosts(
            address_list, timeout=max(connect_timeout, 0.5), concurrency=min(concurrency, 64)
        ),
        scan_tcp_ports(address_list, ports, timeout=connect_timeout, concurrency=concurrency),
    )
    final_neighbors = {
        address: mac
        for address, mac in (await inspect_neighbors()).items()
        if in_networks(address, networks)
    }
    neighbors = initial_neighbors | final_neighbors

    hosts: dict[str, HostRecord] = {}
    for address in set(neighbors) | responsive | set(open_services):
        host = _host_for(hosts, address)
        host.mac = neighbors.get(address)
        host.vendor = lookup_vendor(host.mac)
        host.icmp_responsive = address in responsive
        host.services = open_services.get(address, [])
    for item in ssdp:
        source = item.get("source") or source_from_location(item.get("location", ""))
        if _address_allowed(source, networks):
            _host_for(hosts, source).ssdp.append(item)
    for item in mdns:
        source = item.get("source")
        if _address_allowed(source, networks):
            _host_for(hosts, source).mdns.append(item)
    for item in ws_discovery:
        source = item.get("source")
        if not _address_allowed(source, networks):
            continue
        host = _host_for(hosts, source)
        for endpoint in item.get("xaddrs", []):
            host.onvif.append(OnvifEvidence(endpoint=endpoint, discovered_by="ONVIF WS-Discovery"))

    say(f"Fingerprinting application services on {len(hosts)} responding/neighbor hosts")
    host_list = sorted(hosts.values(), key=lambda item: ipaddress.ip_address(item.address))
    hostname_results = await asyncio.gather(*(reverse_hostname(host.address) for host in host_list))
    for host, hostname in zip(host_list, hostname_results, strict=True):
        host.hostname = hostname
    http_results = await asyncio.gather(
        *(
            probe_http_services(host.address, host.open_ports, timeout=protocol_timeout)
            for host in host_list
        )
    )
    for host, evidence in zip(host_list, http_results, strict=True):
        host.http = [item for item in evidence if item.status is not None]
        score_host(host)

    initial_rtsp_tasks: list[tuple[HostRecord, int, asyncio.Task]] = []
    async with asyncio.TaskGroup() as group:
        for host in host_list:
            probe_ports = {554} if 554 in host.open_ports else set()
            if host.score >= 15:
                probe_ports.update(
                    set(host.open_ports) & {80, 554, 8000, 8080, 8081, 8899, 9000, 34567}
                )
            for port in probe_ports:
                task = group.create_task(
                    probe_rtsp_service(host.address, port, timeout=protocol_timeout)
                )
                initial_rtsp_tasks.append((host, port, task))
    for host, _, task in initial_rtsp_tasks:
        item = task.result()
        if item.confirmed or host.score >= 15:
            host.rtsp.append(item)
    for host in host_list:
        score_host(host)

    candidates = sorted(
        (host for host in host_list if merits_deep_probe(host)),
        key=lambda item: item.score,
        reverse=True,
    )[:8]
    credentials: Credentials | None = None
    auth_seen = any(
        item.auth_type for host in candidates for item in [*host.http, *host.rtsp]
    ) or any(item.auth_required for host in candidates for item in host.onvif)
    if prompt_credentials and (auth_seen or username):
        credentials = await _get_credentials(username)
        if credentials is None:
            result.warnings.append("Credential prompt requested, but stdin was not interactive.")

    if candidates:
        say(f"Deep probing {len(candidates)} evidence-selected candidate(s) only")
    for host in candidates:
        await _investigate_candidate(
            host,
            credentials=credentials,
            test_events=test_events,
            timeout=max(protocol_timeout, 3.0),
        )
        score_host(host)

    likely = [host for host in candidates if host.score >= 20]
    rtsp_channel_count = len(
        {
            stream.channel
            for host in likely
            for stream in host.rtsp
            if stream.confirmed and stream.channel is not None
        }
    )
    api_channel_count = max(
        (api.channel_count or 0 for host in likely for api in host.local_api if api.authenticated),
        default=0,
    )
    internal_wireless = any(
        isinstance(api.results.get("channels"), dict)
        and any(
            _is_isolated_wireless_camera(camera, networks)
            for camera in api.results["channels"].get("IPCamInfo", [])
            if isinstance(camera, dict)
        )
        for host in likely
        for api in host.local_api
    )
    confirmed_kp2p = sum(
        1
        for host in likely
        for protocol in host.kp2p
        for stream in protocol.streams
        if stream.confirmed
    )
    if likely and api_channel_count and internal_wireless:
        result.topology["CONFIRMED"] = (
            f"The NVR manages {api_channel_count} wireless camera channels on an "
            "isolated recorder-managed network."
        )
        if confirmed_kp2p:
            result.topology["CONFIRMED STREAM PROXY"] = (
                f"The LAN-side KP2P service returned video for {confirmed_kp2p} tested "
                "channel/quality mapping(s)."
            )
    elif likely and rtsp_channel_count > 1:
        result.topology["HIGH CONFIDENCE"] = (
            f"The LAN-accessible NVR proxies at least {rtsp_channel_count} distinct camera "
            "channels. "
            "Direct camera reachability is not required."
        )
    elif likely:
        result.topology["HYPOTHESIS"] = (
            "A likely NVR is LAN-accessible; whether its paired cameras live on an isolated "
            "NVR Wi-Fi network cannot yet be confirmed from local protocol evidence."
        )
    else:
        result.topology["HYPOTHESIS"] = (
            "No likely NVR was identified, so the two-layer topology is unresolved."
        )

    result.hosts = host_list
    result.completed_at = _now()
    write_reports(result, artifacts)
    say(f"Reports written to {artifacts.resolve()}")
    return result
