"""Read-only investigator for the local Netsdk API proven by the recorder's web client."""

from __future__ import annotations

from typing import Any

from .models import LocalApiEvidence
from .probes import http_get_json
from .security import Credentials, redact

READ_ENDPOINTS = {
    "device_information": "/netsdk/Stat/DeviceInfo",
    "channels": "/netsdk/Channel",
    "ipc_status": "/netsdk/Stat/IPC",
    "ipc_information": "/netsdk/Channel/IPCamInfo",
    "streams": "/netsdk/Stream",
    "stream_encoding": "/netsdk/Stream/Encode",
    "events": "/netsdk/Event",
}


def _auth_type(header: str | None) -> str | None:
    return header.split(maxsplit=1)[0].lower() if header else None


def _find_channel_count(value: Any) -> int | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"max_chn", "maxchn", "channelcount", "channel_count"}:
                try:
                    return int(item)
                except TypeError, ValueError:
                    pass
        for item in value.values():
            found = _find_channel_count(item)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_channel_count(item)
            if found is not None:
                return found
    return None


async def investigate_netsdk(
    address: str,
    port: int,
    *,
    credentials: Credentials | None = None,
    timeout: float = 3.0,
) -> LocalApiEvidence:
    result = LocalApiEvidence(
        base_url=f"http://{address}:{port}/netsdk",
        auth_type="basic" if credentials else None,
        auth_required=credentials is not None,
    )
    names = list(READ_ENDPOINTS) if credentials else ["device_information"]
    for name in names:
        status, headers, data, error = await http_get_json(
            address,
            port,
            READ_ENDPOINTS[name],
            credentials=credentials,
            timeout=timeout,
        )
        result.auth_type = result.auth_type or _auth_type(headers.get("www-authenticate"))
        if status in {401, 403}:
            result.auth_required = True
            if credentials:
                result.errors.append(f"{name}: authentication failed (HTTP {status})")
            break
        if error:
            result.errors.append(f"{name}: {error}")
            continue
        if status != 200:
            result.errors.append(f"{name}: HTTP {status}")
            continue
        result.authenticated = credentials is not None
        result.results[name] = redact(data)
    result.channel_count = _find_channel_count(result.results.get("device_information"))
    if result.channel_count is None:
        channels = result.results.get("channels")
        if isinstance(channels, list):
            result.channel_count = len(channels)
        elif isinstance(channels, dict):
            for item in channels.values():
                if isinstance(item, list):
                    result.channel_count = len(item)
                    break
    return result
