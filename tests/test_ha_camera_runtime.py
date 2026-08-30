from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from http import HTTPStatus
from unittest.mock import PropertyMock, patch

import pytest
from homeassistant.components import camera as camera_component
from homeassistant.components.camera import Camera
from homeassistant.components.camera.helper import get_camera_from_entity_id
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.jooan_nvr.camera import JooanCamera
from custom_components.jooan_nvr.client import JooanClient
from custom_components.jooan_nvr.const import (
    CONF_DEVICE_ID,
    CONF_HTTP_PORT,
    CONF_KP2P_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_KP2P_PORT,
    DOMAIN,
    OPT_PREFERRED_STREAM,
    STREAM_SUB,
)
from custom_components.jooan_nvr.kp2p import Kp2pError, VideoFrame
from custom_components.jooan_nvr.models import Channel, ChannelStatus, NvrIdentity

pytestmark = pytest.mark.usefixtures("socket_enabled")

DEVICE_ID = "0123456789abcdef01234567"
H264_KEYFRAME = base64.b64decode(
    "AAAAAWdCwArd6EAAAAMAQAAAB6PEieAAAAABaM4PyAAAAWWIhDoRigACSrHAAERmOAAIjOA="
)
H264_NEXT_KEYFRAME = base64.b64decode(
    "AAAAAWdCwArd6EAAAAMAQAAAB6PEieAAAAABaM4PyAAAAWWIggJoRigACmXHAAElOOAAJKeA"
)
JPEG_IMAGE = b"\xff\xd8jooan-runtime-frame\xff\xd9"


class _TurboJpeg:
    def encode(self, _image: object) -> bytes:
        return JPEG_IMAGE


class _RuntimeLiveStream:
    attempts = 0
    failures_remaining = 0

    @classmethod
    def reset(cls, *, failures: int = 0) -> None:
        cls.attempts = 0
        cls.failures_remaining = failures

    def __init__(
        self,
        session: object,
        host: str,
        port: int,
        username: str,
        password: str,
        channel: int,
        stream_id: int,
        *,
        stage_callback: Callable[[str], None] | None = None,
    ) -> None:
        del session, host, port, username, password, stream_id
        self.channel = channel
        self.stage_callback = stage_callback
        type(self).attempts += 1
        self.attempt = type(self).attempts

    async def __aenter__(self) -> _RuntimeLiveStream:
        if self.stage_callback:
            for stage in (
                "KP2P websocket connecting",
                "KP2P websocket connected",
                "ARQ handshake complete",
                "KP2P authentication complete",
                "live-stream request accepted",
            ):
                self.stage_callback(stage)
        return self

    async def __aexit__(self, *args: object) -> None:
        del args

    async def async_frames(self):  # type: ignore[no-untyped-def]
        if self.attempt <= type(self).failures_remaining:
            raise Kp2pError("synthetic initial stream failure", stage="no video frames")
        frames = (H264_KEYFRAME, H264_NEXT_KEYFRAME)
        index = 0
        while True:
            yield VideoFrame(self.channel, 1, "H264", 15.0, 16, 16, frames[index % 2])
            index += 1
            await asyncio.sleep(0.01)


async def _setup_runtime_camera(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
    *,
    failures: int = 0,
) -> tuple[MockConfigEntry, JooanCamera]:
    identity = NvrIdentity(DEVICE_ID, "Test NVR", "JA-8108-W", "3.0.6.0", 1)
    channel = Channel(1, "CAM2", "IPCAM", "2.4.13", None, "Wireless")
    statuses = {1: ChannelStatus(1, True, True, 39, "Connect success")}

    async def async_get_identity(_client: JooanClient) -> NvrIdentity:
        return identity

    async def async_get_channels(_client: JooanClient, _count: int) -> tuple[Channel, ...]:
        return (channel,)

    async def async_get_statuses(_client: JooanClient) -> dict[int, ChannelStatus]:
        return statuses

    monkeypatch.setattr(JooanClient, "async_get_identity", async_get_identity)
    monkeypatch.setattr(JooanClient, "async_get_channels", async_get_channels)
    monkeypatch.setattr(JooanClient, "async_get_statuses", async_get_statuses)
    monkeypatch.setattr("custom_components.jooan_nvr.bridge.Kp2pLiveStream", _RuntimeLiveStream)
    monkeypatch.setattr(
        "homeassistant.components.camera.TurboJPEGSingleton.instance",
        lambda: _TurboJpeg(),
    )
    _RuntimeLiveStream.reset(failures=failures)

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
        options={OPT_PREFERRED_STREAM: STREAM_SUB},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    camera_states = hass.states.async_all(camera_component.DOMAIN)
    assert len(camera_states) == 1
    camera = get_camera_from_entity_id(hass, camera_states[0].entity_id)
    assert isinstance(camera, JooanCamera)
    return entry, camera


async def _get_camera_image_with_retry(client: object, entity_picture: str) -> bytes:
    async with asyncio.timeout(5):
        while True:
            response = await client.get(entity_picture)  # type: ignore[attr-defined]
            content = await response.read()
            if response.status == HTTPStatus.OK:
                return content
            assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
            await asyncio.sleep(0.05)


async def _stop_camera(entry: MockConfigEntry, camera: JooanCamera, hass: HomeAssistant) -> None:
    if camera.stream:
        for provider in camera.stream.outputs().values():
            await camera.stream.remove_provider(provider)
    await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_frontend_still_then_picture_entity_live_path(
    hass: HomeAssistant,
    hass_client,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry, camera = await _setup_runtime_camera(hass, monkeypatch)
    client = await hass_client()
    state = hass.states.get(camera.entity_id)
    assert state is not None
    assert camera.available is True
    assert camera.use_stream_for_stills is True
    entity_picture = state.attributes["entity_picture"]

    with (
        patch.object(
            JooanCamera,
            "use_stream_for_stills",
            new_callable=PropertyMock,
            return_value=True,
        ) as use_stream_for_stills,
        patch.object(
            Camera,
            "camera_image",
            autospec=True,
            side_effect=AssertionError("default camera_image must not be called"),
        ) as camera_image,
        patch.object(camera, "stream_source", wraps=camera.stream_source) as stream_source,
    ):
        # The proxy endpoint is the entity-picture path used by more-info.
        assert await _get_camera_image_with_retry(client, entity_picture) == JPEG_IMAGE
        assert await _get_camera_image_with_retry(client, entity_picture) == JPEG_IMAGE

        # This is the HLS request made by Picture Entity with camera_view: live.
        first_url = await camera_component.async_request_stream(hass, camera.entity_id, "hls")
        second_url = await camera_component.async_request_stream(hass, camera.entity_id, "hls")
        assert first_url == second_url
        response = await client.get(first_url)
        playlist = await response.text()
        assert response.status == HTTPStatus.OK
        assert "#EXTM3U" in playlist

    camera_image.assert_not_called()
    assert use_stream_for_stills.call_count >= 2
    stream_source.assert_awaited_once()
    assert _RuntimeLiveStream.attempts == 1
    assert camera.stream is not None
    assert camera.stream.available is True
    assert camera.available is True
    await _stop_camera(entry, camera, hass)


@pytest.mark.asyncio
async def test_home_assistant_stream_failure_automatically_recovers(
    hass: HomeAssistant,
    hass_client,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry, camera = await _setup_runtime_camera(hass, monkeypatch, failures=1)
    client = await hass_client()
    availability_history: list[bool] = []
    original_write_state = camera.async_write_ha_state

    def record_availability() -> None:
        availability_history.append(camera.available)
        original_write_state()

    with (
        patch.object(camera, "async_write_ha_state", side_effect=record_availability),
        patch("homeassistant.components.stream.STREAM_RESTART_INCREMENT", 0),
    ):
        live_url = await camera_component.async_request_stream(hass, camera.entity_id, "hls")
        async with asyncio.timeout(5):
            while _RuntimeLiveStream.attempts < 2 or False not in availability_history:
                await asyncio.sleep(0.01)

        response = await client.get(live_url)
        assert response.status == HTTPStatus.OK
        assert "#EXTM3U" in await response.text()

    assert False in availability_history
    assert availability_history[-1] is True
    assert camera.channel_status is not None and camera.channel_status.online is True
    assert camera.stream is not None and camera.stream.available is True
    assert camera.available is True
    assert _RuntimeLiveStream.attempts == 2
    await _stop_camera(entry, camera, hass)
