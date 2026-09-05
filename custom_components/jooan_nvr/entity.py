"""Shared JOOAN channel entity behavior."""

from __future__ import annotations

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import JooanRuntimeData
from .const import DOMAIN, MANUFACTURER
from .models import Channel, ChannelStatus


class JooanChannelEntity(CoordinatorEntity):
    """Base class for entities belonging to a recorder channel."""

    _attr_has_entity_name = True

    def __init__(self, runtime: JooanRuntimeData, channel: Channel) -> None:
        super().__init__(runtime.coordinator)
        self.runtime = runtime
        self.channel = channel
        connections: set[tuple[str, str]] = set()
        if channel.mac:
            connections.add((dr.CONNECTION_NETWORK_MAC, channel.mac))
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{runtime.identity.device_id}:channel:{channel.channel_id}")},
            connections=connections,
            name=channel.name,
            manufacturer=MANUFACTURER,
            model=channel.model,
            sw_version=channel.firmware,
            via_device_id=runtime.nvr_device_id,
        )

    @property
    def channel_status(self) -> ChannelStatus | None:
        """Return the latest state for this channel."""
        return self.coordinator.data.get(self.channel.channel_id)
