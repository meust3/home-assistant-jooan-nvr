"""JSON and human-readable evidence report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import HostRecord, ScanResult
from .security import redact


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(redact(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_reports(result: ScanResult, artifacts: Path) -> tuple[Path, Path, Path]:
    artifacts.mkdir(parents=True, exist_ok=True)
    all_data = result.as_dict()
    network_scan = {
        "schema_version": result.schema_version,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "networks": all_data["networks"],
        "protocol_discovery": all_data["protocol_discovery"],
        "hosts": [
            {
                "address": host.address,
                "hostname": host.hostname,
                "mac": host.mac,
                "vendor": host.vendor,
                "icmp_responsive": host.icmp_responsive,
                "services": [asdict(item) for item in host.services],
            }
            for host in result.hosts
        ],
        "optional_tools": result.optional_tools,
        "warnings": result.warnings,
    }
    candidate_hosts = [host for host in result.hosts if host.score > 0 or host.onvif or host.rtsp]
    device_report = {
        "schema_version": result.schema_version,
        "generated_at": result.completed_at,
        "networks": all_data["networks"],
        "candidates": [
            asdict(host) for host in sorted(candidate_hosts, key=lambda h: h.score, reverse=True)
        ],
        "topology": result.topology,
        "warnings": result.warnings,
    }
    scan_path = artifacts / "network-scan.json"
    device_path = artifacts / "device-report.json"
    markdown_path = artifacts / "device-report.md"
    _write_json(scan_path, network_scan)
    _write_json(device_path, device_report)
    markdown_path.write_text(redact(_markdown(result, candidate_hosts)), encoding="utf-8")
    return scan_path, device_path, markdown_path


def _value(value: Any) -> str:
    return str(value) if value not in (None, "", [], {}) else "Not observed"


def _host_markdown(host: HostRecord) -> list[str]:
    lines = [
        f"## {host.address} — {host.score}% likely JOOAN/EseeCloud NVR",
        "",
        f"**Assessment: {host.confidence}**",
        "",
        f"- Hostname: {_value(host.hostname)}",
        f"- MAC: {_value(host.mac)}",
        f"- OUI/vendor: {_value(host.vendor)}",
        f"- ICMP responsive: {host.icmp_responsive}",
        f"- Open TCP ports: {_value(', '.join(map(str, host.open_ports)))}",
        "",
        "### Identity evidence",
        "",
    ]
    lines.extend(f"- {reason}" for reason in host.score_reasons)
    if not host.score_reasons:
        lines.append("- No identity evidence supports this hypothesis.")
    lines.extend(["", "### Services", ""])
    for item in host.http:
        detail = f"HTTP {item.status}" if item.status else item.error or "No HTTP response"
        lines.append(
            f"- `{item.url}` — {detail}; server={_value(item.server)}; "
            f"title={_value(item.title)}; auth={_value(item.auth_type)}; "
            f"app indicators={_value(item.indicators)}"
        )
    for item in host.services:
        if item.protocol != "unknown":
            lines.append(
                f"- {item.transport.upper()} port {item.port} — protocol={item.protocol}; "
                f"state={item.state}; banner={_value(item.banner)}"
            )
    for item in host.rtsp:
        if item.path == "/":
            lines.append(
                f"- RTSP port {item.port} — status={_value(item.status)}; "
                f"server={_value(item.server)}; auth={_value(item.auth_type)}; "
                f"error={_value(item.error)}"
            )
    if not host.http and not host.rtsp:
        lines.append("- No application protocol fingerprint collected.")

    lines.extend(["", "### Local Netsdk API", ""])
    if not host.local_api:
        lines.append("- **NOT SUPPORTED:** no proven local Netsdk API was investigated.")
    for item in host.local_api:
        label = "CONFIRMED" if item.authenticated else "HIGH CONFIDENCE"
        lines.append(f"- **{label}:** `{item.base_url}`")
        lines.append(f"  - Authentication: {_value(item.auth_type)}")
        lines.append(f"  - Credentials required: {item.auth_required}")
        lines.append(f"  - Authenticated: {item.authenticated}")
        lines.append(f"  - Channel count: {_value(item.channel_count)}")
        lines.append(f"  - Read endpoints returned: {_value(sorted(item.results))}")
        if item.results:
            lines.append(f"  - Redacted response data: {_value(item.results)}")
        if item.errors:
            lines.append(f"  - Errors/unknowns: {'; '.join(item.errors)}")

    lines.extend(["", "### Local KP2P streams", ""])
    if not host.kp2p:
        lines.append(
            "- **HYPOTHESIS:** KP2P WebSocket is present but live video was not authenticated."
        )
    for protocol in host.kp2p:
        label = "CONFIRMED" if any(item.confirmed for item in protocol.streams) else "HYPOTHESIS"
        lines.append(
            f"- **{label}:** `{protocol.endpoint}`; authenticated={protocol.authenticated}"
        )
        for item in protocol.streams:
            stream_label = "CONFIRMED" if item.confirmed else "NOT SUPPORTED"
            lines.append(
                f"  - **{stream_label}:** channel={item.channel} stream={item.stream} "
                f"(id={item.stream_id}) result={_value(item.open_result)} "
                f"codec={_value(item.codec)} resolution={_value(item.resolution)} "
                f"fps={_value(item.frame_rate)} bitrate={_value(item.bitrate)} "
                f"audio={_value(item.audio_codec)} frames={item.video_frames}/{item.audio_frames} "
                f"latency={_value(item.startup_latency_ms)} ms error={_value(item.error)}"
            )
        if protocol.errors:
            lines.append(f"  - Errors/unknowns: {'; '.join(protocol.errors)}")

    lines.extend(["", "### ONVIF", ""])
    if not host.onvif:
        lines.append("- **NOT SUPPORTED:** no ONVIF endpoint was found or validated.")
    for item in host.onvif:
        label = (
            "CONFIRMED"
            if item.reachable
            else "HYPOTHESIS"
            if item.discovered_by == "ONVIF WS-Discovery"
            else "NOT SUPPORTED"
        )
        lines.append(f"- **{label}:** `{item.endpoint}` ({item.discovered_by})")
        lines.append(f"  - Device information: {_value(item.device_information)}")
        lines.append(
            f"  - Profiles: {len(item.profiles)}; video sources: {len(item.video_sources)}"
        )
        lines.append(f"  - Stream URIs: {len(item.stream_uris)}")
        lines.append(
            f"  - Events: {_value(item.event_service)}; topics: {_value(item.event_topics)}"
        )
        lines.append(f"  - PullPoint tested/supported: {_value(item.pullpoint_supported)}")
        lines.append(
            f"  - PTZ capability advertised (no movement sent): {_value(item.ptz_service)}"
        )
        if item.errors:
            lines.append(f"  - Errors/unknowns: {'; '.join(item.errors)}")

    streams = [item for item in host.rtsp if item.path != "/"]
    lines.extend(["", "### RTSP channel mapping", ""])
    if not streams:
        lines.append(
            "- **NOT SUPPORTED:** no RTSP-capable service was confirmed. Port 554 was closed "
            "and the candidate's web port rejected RTSP, so path guesses were not blindly sent."
        )
    else:
        for item in streams:
            label = "CONFIRMED" if item.confirmed else "HYPOTHESIS"
            lines.append(
                f"- **{label}:** channel={_value(item.channel)} "
                f"stream={_value(item.stream)} path=`{item.path}` status={_value(item.status)} "
                f"codec={_value(item.codec)} resolution={_value(item.resolution)} "
                f"fps={_value(item.frame_rate)} bitrate={_value(item.bitrate)} "
                f"audio={_value(item.audio_codec)} "
                f"latency={_value(item.startup_latency_ms)} ms auth={_value(item.auth_type)}"
            )
    return lines


def _markdown(result: ScanResult, candidates: list[HostRecord]) -> str:
    lines = [
        "# JOOAN / EseeCloud local discovery report",
        "",
        f"Scan started: `{result.started_at}`  ",
        f"Scan completed: `{result.completed_at}`",
        "",
        "## Detected networks",
        "",
    ]
    for item in result.networks:
        state = "SCANNED" if item.selected else "NOT SCANNED"
        lines.append(
            f"- **{state}:** `{item.network}` via {item.interface} ({item.address}) — {item.reason}"
        )
    lines.extend(["", "## Candidate summary", ""])
    if candidates:
        for host in sorted(candidates, key=lambda item: item.score, reverse=True):
            lines.append(f"- `{host.address}` — {host.score}% — **{host.confidence}**")
    else:
        lines.append("- **NOT SUPPORTED:** no candidate device was identified in this run.")
    lines.extend(["", "## Network topology", ""])
    if result.topology:
        for label, detail in result.topology.items():
            lines.append(f"- **{label}:** {detail}")
    else:
        lines.append("- **HYPOTHESIS:** topology could not be determined from this run.")
    lines.extend(["", "## Candidate details", ""])
    for host in sorted(candidates, key=lambda item: item.score, reverse=True):
        lines.extend(_host_markdown(host))
        lines.append("")
    lines.extend(["## Remaining unknowns", ""])
    confirmed_streams = sum(
        1 for host in candidates for stream in host.rtsp if stream.path != "/" and stream.confirmed
    ) + sum(
        1
        for host in candidates
        for protocol in host.kp2p
        for stream in protocol.streams
        if stream.confirmed
    )
    if not confirmed_streams:
        lines.append("- No working local live stream has yet been authenticated and characterized.")
    if any(
        api.auth_required and not api.authenticated for host in candidates for api in host.local_api
    ):
        lines.append(
            "- Local Netsdk credentials are required to retrieve model, channel, stream, "
            "and event data."
        )
    if not any(item.onvif and any(o.reachable for o in item.onvif) for item in candidates):
        lines.append(
            "- ONVIF was not advertised through WS-Discovery and the standard device endpoint "
            "was not supported in this run."
        )
    if not candidates:
        lines.append("- The NVR identity and address remain unknown.")
    lines.append(
        "- Stage 2 is intentionally deferred until local protocol and channel evidence is "
        "sufficient."
    )
    if result.warnings:
        lines.extend(["", "## Scanner warnings", ""])
        lines.extend(f"- {item}" for item in result.warnings)
    return "\n".join(lines).rstrip() + "\n"
