"""Proven channel-state binary sensors for JOOAN NVR."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
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
    """Create connectivity and recording entities for every channel."""
    del hass
    runtime = entry.runtime_data
    entities = []
    for channel in runtime.channels:
        entities.extend(
            (JooanChannelOnline(runtime, channel), JooanChannelRecording(runtime, channel))
        )
    async_add_entities(entities)


class JooanChannelOnline(JooanChannelEntity, BinarySensorEntity):
    """Recorder-reported camera connection state."""

    _attr_translation_key = "online"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime: JooanRuntimeData, channel: Channel) -> None:
        super().__init__(runtime, channel)
        self._attr_unique_id = f"{runtime.identity.device_id}_channel_{channel.channel_id}_online"

    @property
    def is_on(self) -> bool:
        """Return whether the recorder currently sees this channel."""
        return bool(self.channel_status and self.channel_status.online)


class JooanChannelRecording(JooanChannelEntity, BinarySensorEntity):
    """Recorder-reported per-channel recording state."""

    _attr_translation_key = "recording"

    def __init__(self, runtime: JooanRuntimeData, channel: Channel) -> None:
        super().__init__(runtime, channel)
        self._attr_unique_id = (
            f"{runtime.identity.device_id}_channel_{channel.channel_id}_recording"
        )

    @property
    def available(self) -> bool:
        """Recording state is meaningful only while the channel is online."""
        status = self.channel_status
        return super().available and status is not None and status.online

    @property
    def is_on(self) -> bool:
        """Return whether this channel is currently recording."""
        return bool(self.channel_status and self.channel_status.recording)
