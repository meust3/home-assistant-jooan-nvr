"""Privacy-preserving diagnostics for JOOAN NVR."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_HOST, CONF_PASSWORD
from homeassistant.core import HomeAssistant

from . import JooanConfigEntry
from .const import (
    CONF_DEVICE_ID,
    CONF_MAC,
    DEFAULT_STREAM,
    OPT_PREFERRED_STREAM,
    TRANSPORT,
)

TO_REDACT = {CONF_PASSWORD, CONF_HOST, CONF_MAC, CONF_DEVICE_ID}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: JooanConfigEntry
) -> dict[str, Any]:
    """Return useful details without credentials or sensitive hardware IDs."""
    del hass
    runtime = entry.runtime_data
    statuses = runtime.coordinator.data
    return {
        "entry": async_redact_data(dict(entry.data), TO_REDACT),
        "nvr": {
            "name": runtime.identity.name,
            "model": runtime.identity.model,
            "firmware": runtime.identity.firmware,
            "channel_count": runtime.identity.channel_count,
        },
        "transport": {
            "selected": TRANSPORT,
            "services": ["http/netsdk", "websocket/kp2p"],
            "preferred_stream": entry.options.get(OPT_PREFERRED_STREAM, DEFAULT_STREAM),
            "mapping": "zero-based channel; stream 0=main, stream 1=sub",
            "bridge": "on-demand loopback MPEG-TS remux (no decode/transcode)",
        },
        "channels": [
            {
                "id": channel.channel_id,
                "name": channel.name,
                "model": channel.model,
                "firmware": channel.firmware,
                "interface": channel.interface,
                "mac": "**REDACTED**" if channel.mac else None,
                "online": statuses.get(channel.channel_id).online
                if statuses.get(channel.channel_id)
                else None,
                "recording": statuses.get(channel.channel_id).recording
                if statuses.get(channel.channel_id)
                else None,
                "profiles": [
                    {
                        "id": profile.stream_id,
                        "name": profile.name,
                        "codec": profile.codec,
                        "resolution": profile.resolution,
                        "frame_rate": profile.frame_rate,
                        "configured_bitrate": profile.configured_bitrate,
                    }
                    for profile in channel.profiles
                ],
            }
            for channel in runtime.channels
        ],
        "last_update_success": runtime.coordinator.last_update_success,
        "motion_events": "not exposed; local event transitions have not been proven",
    }
