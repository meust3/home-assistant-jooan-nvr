"""Serializable discovery result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class NetworkInfo:
    interface: str
    address: str
    network: str
    netmask: str
    broadcast: str | None
    selected: bool
    reason: str


@dataclass(slots=True)
class ServiceEvidence:
    port: int
    transport: str = "tcp"
    protocol: str = "unknown"
    state: str = "open"
    banner: str | None = None


@dataclass(slots=True)
class HttpEvidence:
    url: str
    status: int | None = None
    server: str | None = None
    title: str | None = None
    auth_type: str | None = None
    content_type: str | None = None
    favicon_sha256: str | None = None
    indicators: list[str] = field(default_factory=list)
    tls: dict[str, Any] | None = None
    error: str | None = None


@dataclass(slots=True)
class RtspEvidence:
    port: int
    path: str
    status: int | None
    server: str | None = None
    auth_type: str | None = None
    methods: list[str] = field(default_factory=list)
    channel: int | None = None
    stream: str | None = None
    codec: str | None = None
    resolution: str | None = None
    frame_rate: float | None = None
    bitrate: int | None = None
    audio_codec: str | None = None
    startup_latency_ms: int | None = None
    uri: str | None = None
    confirmed: bool = False
    error: str | None = None


@dataclass(slots=True)
class OnvifEvidence:
    endpoint: str
    discovered_by: str
    reachable: bool = False
    auth_required: bool = False
    device_information: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, str] = field(default_factory=dict)
    profiles: list[dict[str, Any]] = field(default_factory=list)
    video_sources: list[dict[str, Any]] = field(default_factory=list)
    stream_uris: list[dict[str, Any]] = field(default_factory=list)
    event_service: bool | None = None
    event_topics: list[str] = field(default_factory=list)
    pullpoint_supported: bool | None = None
    ptz_service: bool | None = None
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LocalApiEvidence:
    base_url: str
    auth_type: str | None = None
    auth_required: bool = False
    authenticated: bool = False
    channel_count: int | None = None
    results: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Kp2pStreamEvidence:
    channel: int
    stream_id: int
    stream: str
    open_result: int | None = None
    confirmed: bool = False
    codec: str | None = None
    resolution: str | None = None
    frame_rate: float | None = None
    bitrate: int | None = None
    audio_codec: str | None = None
    video_frames: int = 0
    audio_frames: int = 0
    startup_latency_ms: int | None = None
    error: str | None = None


@dataclass(slots=True)
class Kp2pEvidence:
    endpoint: str
    authenticated: bool = False
    streams: list[Kp2pStreamEvidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HostRecord:
    address: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    icmp_responsive: bool = False
    services: list[ServiceEvidence] = field(default_factory=list)
    http: list[HttpEvidence] = field(default_factory=list)
    rtsp: list[RtspEvidence] = field(default_factory=list)
    onvif: list[OnvifEvidence] = field(default_factory=list)
    local_api: list[LocalApiEvidence] = field(default_factory=list)
    kp2p: list[Kp2pEvidence] = field(default_factory=list)
    ssdp: list[dict[str, str]] = field(default_factory=list)
    mdns: list[dict[str, Any]] = field(default_factory=list)
    score: int = 0
    confidence: str = "LOW CONFIDENCE"
    score_reasons: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return sorted({service.port for service in self.services if service.state == "open"})


@dataclass(slots=True)
class ScanResult:
    schema_version: int
    started_at: str
    completed_at: str | None = None
    scanner_version: str = "0.1.0"
    networks: list[NetworkInfo] = field(default_factory=list)
    hosts: list[HostRecord] = field(default_factory=list)
    protocol_discovery: dict[str, Any] = field(default_factory=dict)
    optional_tools: dict[str, bool] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    topology: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
