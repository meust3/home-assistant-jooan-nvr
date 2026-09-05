"""JOOAN NVR local integration."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .bridge import StreamBridge, StreamBridgeManager
from .client import (
    JooanAuthenticationError,
    JooanClient,
    JooanConnectionError,
    JooanProtocolError,
)
from .const import (
    CONF_DEVICE_ID,
    CONF_HTTP_PORT,
    CONF_KP2P_PORT,
    CONF_MAC,
    DEFAULT_HTTP_PORT,
    DEFAULT_KP2P_PORT,
    DEFAULT_STREAM,
    DOMAIN,
    MANUFACTURER,
    OPT_PREFERRED_STREAM,
    PLATFORMS,
    STREAM_IDS,
)
from .coordinator import JooanCoordinator
from .models import Channel, NvrIdentity


@dataclass(slots=True)
class JooanRuntimeData:
    """Objects owned by one loaded config entry."""

    client: JooanClient
    coordinator: JooanCoordinator
    identity: NvrIdentity
    nvr_device_id: str  # Home Assistant Device Registry entry ID
    channels: tuple[Channel, ...]
    bridges: StreamBridgeManager


type JooanConfigEntry = ConfigEntry[JooanRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: JooanConfigEntry) -> bool:
    """Set up a JOOAN NVR config entry."""
    session = async_get_clientsession(hass)
    host = entry.data[CONF_HOST]
    http_port = entry.data.get(CONF_HTTP_PORT, DEFAULT_HTTP_PORT)
    kp2p_port = entry.data.get(CONF_KP2P_PORT, DEFAULT_KP2P_PORT)
    username = entry.data[CONF_USERNAME]
    password = entry.data.get(CONF_PASSWORD, "")
    client = JooanClient(session, host, http_port, username, password)
    try:
        identity = await client.async_get_identity()
        channels = await client.async_get_channels(identity.channel_count)
    except JooanAuthenticationError as err:
        raise ConfigEntryAuthFailed("local recorder credentials were rejected") from err
    except (JooanConnectionError, JooanProtocolError) as err:
        raise ConfigEntryNotReady(str(err)) from err

    configured_device_id = entry.data.get(CONF_DEVICE_ID) or entry.unique_id
    if configured_device_id and configured_device_id != identity.device_id:
        raise ConfigEntryNotReady("the configured address belongs to a different recorder")

    coordinator = JooanCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    registry = dr.async_get(hass)
    connections: set[tuple[str, str]] = set()
    if mac := entry.data.get(CONF_MAC):
        connections.add((dr.CONNECTION_NETWORK_MAC, mac))
    nvr_device = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, identity.device_id)},
        connections=connections,
        manufacturer=MANUFACTURER,
        name=identity.name,
        model=identity.model,
        sw_version=identity.firmware,
        configuration_url=f"http://{host}:{http_port}",
    )

    selected_stream = entry.options.get(OPT_PREFERRED_STREAM, DEFAULT_STREAM)
    stream_id = STREAM_IDS.get(selected_stream, STREAM_IDS[DEFAULT_STREAM])

    def bridge_factory(channel: int, quality: int) -> StreamBridge:
        return StreamBridge(
            session,
            host,
            kp2p_port,
            username,
            password,
            channel,
            quality,
        )

    entry.runtime_data = JooanRuntimeData(
        client=client,
        coordinator=coordinator,
        identity=identity,
        nvr_device_id=nvr_device.id,
        channels=channels,
        bridges=StreamBridgeManager(bridge_factory, stream_id),
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: JooanConfigEntry) -> bool:
    """Unload platforms and stop all local stream listeners."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    await entry.runtime_data.bridges.async_stop()
    return unload_ok
