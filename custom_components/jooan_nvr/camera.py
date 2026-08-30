"""Camera entities for recorder-proxied JOOAN channels."""

from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import JooanConfigEntry, JooanRuntimeData
from .entity import JooanChannelEntity
from .models import Channel

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: JooanConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one camera entity for every configured recorder channel."""
    del hass
    runtime = entry.runtime_data
    async_add_entities(JooanCamera(runtime, channel) for channel in runtime.channels)


class JooanCamera(JooanChannelEntity, Camera):
    """A camera stream proxied locally by the NVR."""

    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, runtime: JooanRuntimeData, channel: Channel) -> None:
        # CoordinatorEntity and Camera both derive from Entity, but the
        # CoordinatorEntity initializer does not continue through this class's
        # MRO. Initialize both Home Assistant bases explicitly, as core camera
        # integrations with the same inheritance shape do.
        JooanChannelEntity.__init__(self, runtime, channel)
        Camera.__init__(self)
        self._attr_unique_id = f"{runtime.identity.device_id}_channel_{channel.channel_id}_camera"

    @property
    def use_stream_for_stills(self) -> bool:
        """Tell Home Assistant to generate snapshots from its shared stream."""
        return True

    @property
    def available(self) -> bool:
        """Report recorder, channel, and Home Assistant stream health."""
        status = self.channel_status
        stream_available = self.stream is None or self.stream.available
        return super().available and status is not None and status.online and stream_available

    @property
    def is_recording(self) -> bool:
        """Return the NVR's current recording state for this channel."""
        return bool(self.channel_status and self.channel_status.recording)

    async def stream_source(self) -> str | None:
        """Return an on-demand, credential-free local FFmpeg source."""
        if not self.available:
            return None
        return await self.runtime.bridges.async_source_url(self.channel.channel_id)
