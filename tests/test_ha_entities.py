from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import UpdateFailed
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.jooan_nvr import JooanRuntimeData, async_unload_entry
from custom_components.jooan_nvr.camera import JooanCamera
from custom_components.jooan_nvr.camera import async_setup_entry as async_setup_camera_entry
from custom_components.jooan_nvr.const import DOMAIN
from custom_components.jooan_nvr.coordinator import JooanCoordinator
from custom_components.jooan_nvr.models import Channel, ChannelStatus, NvrIdentity

DEVICE_ID = "0123456789abcdef01234567"


def _runtime(
    hass: HomeAssistant,
) -> tuple[JooanRuntimeData, Channel, MockConfigEntry]:
    entry = MockConfigEntry(domain=DOMAIN, unique_id=DEVICE_ID, data={})
    entry.add_to_hass(hass)
    channel = Channel(1, "CAM2", "IPCAM", "2.4.13", None, "Wireless")
    coordinator = JooanCoordinator(hass, entry, MagicMock())
    coordinator.async_set_updated_data({1: ChannelStatus(1, False, False, 0, "Connect Failed")})
    bridges = MagicMock()
    bridges.async_source_url = AsyncMock(return_value="tcp://127.0.0.1:12345")
    bridges.async_stop = AsyncMock()
    runtime = JooanRuntimeData(
        client=MagicMock(),
        coordinator=coordinator,
        identity=NvrIdentity(DEVICE_ID, "Test NVR", "JA-8108-W", "3.0.6.0", 1),
        channels=(channel,),
        bridges=bridges,
    )
    entry.runtime_data = runtime
    return runtime, channel, entry


@pytest.mark.asyncio
async def test_camera_unavailable_and_recovers(hass: HomeAssistant) -> None:
    runtime, channel, _ = _runtime(hass)
    camera = JooanCamera(runtime, channel)

    assert camera.device_info["via_device"] == (DOMAIN, DEVICE_ID)
    assert camera.use_stream_for_stills is True
    assert camera.stream is None
    assert camera.access_tokens
    assert camera.available is False
    assert await camera.stream_source() is None

    runtime.coordinator.async_set_updated_data(
        {1: ChannelStatus(1, True, True, 39, "Connect success")}
    )

    assert camera.available is True
    assert camera.is_recording is True
    assert await camera.stream_source() == "tcp://127.0.0.1:12345"


def test_camera_availability_includes_supported_stream_health(hass: HomeAssistant) -> None:
    runtime, channel, _ = _runtime(hass)
    camera = JooanCamera(runtime, channel)
    runtime.coordinator.async_set_updated_data(
        {1: ChannelStatus(1, True, True, 39, "Connect success")}
    )

    stream = MagicMock()
    stream.available = False
    camera.stream = stream
    assert camera.available is False

    stream.available = True
    assert camera.available is True


@pytest.mark.asyncio
async def test_camera_platform_creates_channel_entity(hass: HomeAssistant) -> None:
    runtime, _, entry = _runtime(hass)
    added: list[JooanCamera] = []

    await async_setup_camera_entry(hass, entry, lambda entities: added.extend(entities))

    assert len(added) == len(runtime.channels)
    assert added[0].unique_id == f"{DEVICE_ID}_channel_1_camera"


@pytest.mark.asyncio
async def test_camera_unavailable_when_nvr_fails_then_recovers(
    hass: HomeAssistant,
) -> None:
    runtime, channel, _ = _runtime(hass)
    camera = JooanCamera(runtime, channel)
    runtime.coordinator.async_set_updated_data(
        {1: ChannelStatus(1, True, True, 39, "Connect success")}
    )
    assert camera.available is True

    runtime.coordinator.async_set_update_error(UpdateFailed("recorder unavailable"))
    assert camera.available is False

    runtime.coordinator.async_set_updated_data(
        {1: ChannelStatus(1, True, True, 38, "Connect success")}
    )
    assert camera.available is True


@pytest.mark.asyncio
async def test_unload_stops_all_stream_bridges(hass: HomeAssistant) -> None:
    runtime, _, entry = _runtime(hass)
    with patch.object(
        hass.config_entries, "async_unload_platforms", return_value=True
    ) as unload_platforms:
        assert await async_unload_entry(hass, entry) is True

    unload_platforms.assert_awaited_once()
    runtime.bridges.async_stop.assert_awaited_once()
