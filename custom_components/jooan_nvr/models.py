"""Data models for the JOOAN NVR integration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class NvrIdentity:
    """Stable, non-sensitive recorder identity."""

    device_id: str
    name: str
    model: str
    firmware: str | None
    channel_count: int


@dataclass(frozen=True, slots=True)
class StreamProfile:
    """One recorder-proxied stream profile."""

    stream_id: int
    name: str
    codec: str | None
    resolution: str | None
    frame_rate: float | None
    configured_bitrate: str | None


@dataclass(frozen=True, slots=True)
class Channel:
    """Static camera channel metadata."""

    channel_id: int
    name: str
    model: str | None
    firmware: str | None
    mac: str | None
    interface: str | None
    profiles: tuple[StreamProfile, ...] = ()

    def profile(self, stream_id: int) -> StreamProfile | None:
        """Return a stream profile by its recorder stream ID."""
        return next((item for item in self.profiles if item.stream_id == stream_id), None)


@dataclass(frozen=True, slots=True)
class ChannelStatus:
    """Dynamic state for a camera channel."""

    channel_id: int
    online: bool
    recording: bool
    wireless_signal: int | None
    status: str | None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Validated recorder data returned during setup."""

    identity: NvrIdentity
    channels: tuple[Channel, ...]
    statuses: dict[int, ChannelStatus] = field(default_factory=dict)
