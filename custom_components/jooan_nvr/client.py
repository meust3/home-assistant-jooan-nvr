"""Asynchronous read-only client for the local JOOAN Netsdk API."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from typing import Any

from aiohttp import ClientError, ClientResponse, ClientSession, ClientTimeout
from yarl import URL

from .const import MANUFACTURER, REQUEST_TIMEOUT
from .models import Channel, ChannelStatus, NvrIdentity, ProbeResult, StreamProfile

DEVICE_PATH = "/netsdk/Stat/DeviceInfo"
CHANNEL_PATH = "/netsdk/Channel/IPCamInfo"
STREAM_PATH = "/netsdk/Stream"
ENCODING_PATH = "/netsdk/Stream/Encode"
STATUS_PATH = "/netsdk/Stat/IPC"


class JooanError(Exception):
    """Base JOOAN integration exception."""


class JooanAuthenticationError(JooanError):
    """The recorder rejected the configured credentials."""


class JooanConnectionError(JooanError):
    """The recorder could not be reached."""


class JooanProtocolError(JooanError):
    """The recorder returned an unexpected response."""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enable", "enabled"}


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except TypeError, ValueError:
        return None


def _as_list(value: Any, key: str | None = None) -> list[Mapping[str, Any]]:
    if key and isinstance(value, Mapping):
        value = value.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _normalise_mac(value: Any) -> str | None:
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(raw) != 12:
        return None
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2)).lower()


def _stable_device_id(data: Mapping[str, Any]) -> str:
    """Hash sensitive hardware IDs before using them in Home Assistant."""
    raw = str(data.get("UID") or data.get("HWID") or "").strip()
    if not raw:
        raise JooanProtocolError("recorder did not provide a stable hardware identifier")
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _parse_frame_rate(value: Any) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(value or ""))
    return float(match.group(1)) if match else None


class JooanClient:
    """Read the recorder's proven local HTTP API without changing configuration."""

    def __init__(
        self,
        session: ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self.session = session
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = ClientTimeout(total=timeout)

    def _url(self, path: str) -> URL:
        return URL.build(scheme="http", host=self.host, port=self.port, path=path)

    async def _response_json(self, response: ClientResponse, path: str) -> Any:
        if response.status in {401, 403}:
            raise JooanAuthenticationError("invalid local recorder credentials")
        if response.status != 200:
            raise JooanProtocolError(f"{path} returned HTTP {response.status}")
        try:
            return await response.json(content_type=None)
        except (ValueError, TypeError) as err:
            raise JooanProtocolError(f"{path} did not return JSON") from err

    async def async_get_json(self, path: str) -> Any:
        """Fetch one read-only Netsdk resource."""
        credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        try:
            async with self.session.get(
                self._url(path),
                headers={"Authorization": f"Basic {credentials}"},
                timeout=self.timeout,
            ) as response:
                return await self._response_json(response, path)
        except JooanError:
            raise
        except (TimeoutError, ClientError, OSError) as err:
            raise JooanConnectionError(f"could not reach recorder at {self.host}") from err

    async def async_get_identity(self) -> NvrIdentity:
        """Read and validate recorder identity."""
        value = await self.async_get_json(DEVICE_PATH)
        if not isinstance(value, Mapping):
            raise JooanProtocolError("device information was not an object")
        model = str(value.get("DeviceModel") or "").strip()
        support_site = str(value.get("SupportWeb") or "").lower()
        if not model or not (model.upper().startswith("JA-") or "jooan" in support_site):
            raise JooanProtocolError("endpoint is not a validated JOOAN recorder")
        channel_count = _as_int(value.get("MAX_CHN"))
        if not channel_count or channel_count < 1:
            raise JooanProtocolError("recorder did not provide a valid channel count")
        return NvrIdentity(
            device_id=_stable_device_id(value),
            name=str(value.get("DeviceName") or "JOOAN NVR").strip() or "JOOAN NVR",
            model=model,
            firmware=str(value.get("FWVersion") or "").strip() or None,
            channel_count=channel_count,
        )

    async def async_get_channels(self, channel_count: int) -> tuple[Channel, ...]:
        """Read static channel, title, and encoding metadata."""
        camera_data = await self.async_get_json(CHANNEL_PATH)
        stream_data = await self.async_get_json(STREAM_PATH)
        encoding_data = await self.async_get_json(ENCODING_PATH)

        cameras = {
            item_id: item
            for item in _as_list(camera_data)
            if (item_id := _as_int(item.get("ID"))) is not None
        }
        titles = {
            item_id: str(item.get("Text") or "").strip()
            for item in _as_list(stream_data, "Title")
            if (item_id := _as_int(item.get("ID"))) is not None
        }
        encodings = {
            item_id: item
            for item in _as_list(encoding_data)
            if (item_id := _as_int(item.get("ID"))) is not None
        }

        channels: list[Channel] = []
        for channel_id in range(channel_count):
            camera = cameras.get(channel_id, {})
            encoding = encodings.get(channel_id, {})
            profiles: list[StreamProfile] = []
            for item in _as_list(encoding, "Stream"):
                stream_id = _as_int(item.get("ID"))
                if stream_id is None:
                    continue
                profiles.append(
                    StreamProfile(
                        stream_id=stream_id,
                        name=str(item.get("Name") or f"Stream {stream_id}").strip(),
                        codec=str(item.get("CodingFmt") or "").strip() or None,
                        resolution=str(item.get("Format") or "").strip() or None,
                        frame_rate=_parse_frame_rate(item.get("Framerate")),
                        configured_bitrate=str(item.get("BitrateValue") or "").strip() or None,
                    )
                )
            channels.append(
                Channel(
                    channel_id=channel_id,
                    name=titles.get(channel_id) or f"Camera {channel_id + 1}",
                    model=str(camera.get("Modelname") or "").strip() or None,
                    firmware=str(camera.get("SWVersion") or "").strip() or None,
                    mac=_normalise_mac(camera.get("MACAddr")),
                    interface=str(camera.get("InterfaceType") or "").strip() or None,
                    profiles=tuple(sorted(profiles, key=lambda item: item.stream_id)),
                )
            )
        return tuple(channels)

    async def async_get_statuses(self) -> dict[int, ChannelStatus]:
        """Read the current channel connectivity and recording state."""
        value = await self.async_get_json(STATUS_PATH)
        statuses: dict[int, ChannelStatus] = {}
        for item in _as_list(value):
            channel_id = _as_int(item.get("ID"))
            if channel_id is None:
                continue
            statuses[channel_id] = ChannelStatus(
                channel_id=channel_id,
                online=_as_bool(item.get("BcamOnline")),
                recording=_as_bool(item.get("RecordingState")),
                wireless_signal=_as_int(item.get("WifiSignal")),
                status=str(item.get("Status") or "").strip() or None,
            )
        if not statuses:
            raise JooanProtocolError("recorder returned no channel status records")
        return statuses

    async def async_probe(self) -> ProbeResult:
        """Validate credentials and enumerate the proven channel mapping."""
        identity = await self.async_get_identity()
        channels = await self.async_get_channels(identity.channel_count)
        statuses = await self.async_get_statuses()
        return ProbeResult(identity=identity, channels=channels, statuses=statuses)


__all__ = [
    "JooanAuthenticationError",
    "JooanClient",
    "JooanConnectionError",
    "JooanError",
    "JooanProtocolError",
    "MANUFACTURER",
]
