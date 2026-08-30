"""Coordinated status polling for JOOAN NVR channels."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import (
    JooanAuthenticationError,
    JooanClient,
    JooanConnectionError,
    JooanProtocolError,
)
from .const import DOMAIN, UPDATE_INTERVAL
from .models import ChannelStatus

_LOGGER = logging.getLogger(__name__)


class JooanCoordinator(DataUpdateCoordinator[dict[int, ChannelStatus]]):
    """Poll all channel states in one conservative request."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: JooanClient,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
            always_update=False,
        )
        self.client = client

    async def _async_update_data(self) -> dict[int, ChannelStatus]:
        try:
            return await self.client.async_get_statuses()
        except JooanAuthenticationError as err:
            raise ConfigEntryAuthFailed("local recorder credentials were rejected") from err
        except (JooanConnectionError, JooanProtocolError) as err:
            raise UpdateFailed(str(err)) from err
