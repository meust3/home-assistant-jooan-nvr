from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.components.binary_sensor import DOMAIN as BINARY_SENSOR_DOMAIN
from homeassistant.components.camera import DOMAIN as CAMERA_DOMAIN
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    STATE_OFF,
    STATE_ON,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import UpdateFailed
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.jooan_nvr import JooanRuntimeData, async_unload_entry
from custom_components.jooan_nvr.camera import JooanCamera
from custom_components.jooan_nvr.camera import async_setup_entry as async_setup_camera_entry
from custom_components.jooan_nvr.client import JooanClient
from custom_components.jooan_nvr.const import (
    CONF_DEVICE_ID,
    CONF_HTTP_PORT,
    CONF_KP2P_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_KP2P_PORT,
    DOMAIN,
)
from custom_components.jooan_nvr.coordinator import JooanCoordinator
from custom_components.jooan_nvr.models import Channel, ChannelStatus, NvrIdentity

DEVICE_ID = "0123456789abcdef01234567"
NVR_DEVICE_REGISTRY_ID = "test-ha-parent-device-id"


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
        nvr_device_id=NVR_DEVICE_REGISTRY_ID,
        channels=(channel,),
        bridges=bridges,
    )
    entry.runtime_data = runtime
    return runtime, channel, entry


@pytest.mark.asyncio
async def test_camera_unavailable_and_recovers(hass: HomeAssistant) -> None:
    runtime, channel, _ = _runtime(hass)
    camera = JooanCamera(runtime, channel)

    assert camera.device_info["via_device_id"] == NVR_DEVICE_REGISTRY_ID
    assert "via_device" not in camera.device_info
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


@pytest.mark.usefixtures("socket_enabled")
@pytest.mark.asyncio
async def test_config_entry_registers_channel_entities_under_parent_device(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = NvrIdentity(DEVICE_ID, "Test NVR", "JA-8108-W", "3.0.6.0", 2)
    channels = (
        Channel(1, "CAM2", "IPCAM", "2.4.13", None, "Wireless"),
        Channel(2, "CAM3", "IPCAM", "2.4.13", None, "Wireless"),
    )
    statuses = {
        1: ChannelStatus(1, True, True, 39, "Connect success"),
        2: ChannelStatus(2, False, False, 0, "Connect Failed"),
    }

    async def async_get_identity(_client: JooanClient) -> NvrIdentity:
        return identity

    async def async_get_channels(_client: JooanClient, _count: int) -> tuple[Channel, ...]:
        return channels

    async def async_get_statuses(_client: JooanClient) -> dict[int, ChannelStatus]:
        return statuses

    monkeypatch.setattr(JooanClient, "async_get_identity", async_get_identity)
    monkeypatch.setattr(JooanClient, "async_get_channels", async_get_channels)
    monkeypatch.setattr(JooanClient, "async_get_statuses", async_get_statuses)

    assert await async_setup_component(hass, "stream", {"stream": {}})
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DEVICE_ID,
        data={
            CONF_HOST: "192.168.77.10",
            CONF_HTTP_PORT: DEFAULT_HTTP_PORT,
            CONF_KP2P_PORT: DEFAULT_KP2P_PORT,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "",
            CONF_DEVICE_ID: DEVICE_ID,
        },
    )
    entry.add_to_hass(hass)

    entity_registry = er.async_get(hass)
    existing_unique_id = f"{DEVICE_ID}_channel_1_camera"
    existing_camera = entity_registry.async_get_or_create(
        CAMERA_DOMAIN,
        DOMAIN,
        existing_unique_id,
        suggested_object_id="cam_front_gate",
        config_entry=entry,
    )
    assert existing_camera.entity_id == "camera.cam_front_gate"

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    device_registry = dr.async_get(hass)
    parent = device_registry.async_get_device_by_identifier((DOMAIN, DEVICE_ID), entry.entry_id)
    assert parent is not None
    assert parent.id != DEVICE_ID
    assert entry.runtime_data.nvr_device_id == parent.id

    config_devices = dr.async_entries_for_config_entry(device_registry, entry.entry_id)
    assert len(config_devices) == 3
    config_entities = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
    assert len(config_entities) == 6

    for channel in channels:
        child = device_registry.async_get_device_by_identifier(
            (DOMAIN, f"{DEVICE_ID}:channel:{channel.channel_id}"), entry.entry_id
        )
        assert child is not None
        assert child.via_device_id == parent.id

        unique_ids = {
            CAMERA_DOMAIN: f"{DEVICE_ID}_channel_{channel.channel_id}_camera",
            "online": f"{DEVICE_ID}_channel_{channel.channel_id}_online",
            "recording": f"{DEVICE_ID}_channel_{channel.channel_id}_recording",
        }
        for entity_type, unique_id in unique_ids.items():
            domain = CAMERA_DOMAIN if entity_type == CAMERA_DOMAIN else BINARY_SENSOR_DOMAIN
            entity_id = entity_registry.async_get_entity_id(domain, DOMAIN, unique_id)
            assert entity_id is not None
            registry_entry = entity_registry.async_get(entity_id)
            assert registry_entry is not None
            assert registry_entry.device_id == child.id

    assert entity_registry.async_get_entity_id(CAMERA_DOMAIN, DOMAIN, existing_unique_id) == (
        "camera.cam_front_gate"
    )
    online_camera_state = hass.states.get("camera.cam_front_gate")
    assert online_camera_state is not None
    assert online_camera_state.state != STATE_UNAVAILABLE

    offline_camera_id = entity_registry.async_get_entity_id(
        CAMERA_DOMAIN, DOMAIN, f"{DEVICE_ID}_channel_2_camera"
    )
    assert offline_camera_id is not None
    offline_camera_state = hass.states.get(offline_camera_id)
    assert offline_camera_state is not None
    assert offline_camera_state.state == STATE_UNAVAILABLE

    expected_binary_states = {
        f"{DEVICE_ID}_channel_1_online": STATE_ON,
        f"{DEVICE_ID}_channel_1_recording": STATE_ON,
        f"{DEVICE_ID}_channel_2_online": STATE_OFF,
        f"{DEVICE_ID}_channel_2_recording": STATE_UNAVAILABLE,
    }
    for unique_id, expected_state in expected_binary_states.items():
        entity_id = entity_registry.async_get_entity_id(BINARY_SENSOR_DOMAIN, DOMAIN, unique_id)
        assert entity_id is not None
        state = hass.states.get(entity_id)
        assert state is not None
        assert state.state == expected_state

    assert await hass.config_entries.async_unload(entry.entry_id)


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
