from __future__ import annotations

import asyncio
import base64
import io
import logging
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from unittest.mock import MagicMock

import av
import pytest

from custom_components.jooan_nvr.bridge import StreamBridge, _MpegTsMuxer
from custom_components.jooan_nvr.kp2p import Kp2pError, VideoFrame

pytestmark = pytest.mark.usefixtures("socket_enabled")

H264_KEYFRAME = base64.b64decode(
    "AAAAAWdCwArd6EAAAAMAQAAAB6PEieAAAAABaM4PyAAAAWWIhDoRigACSrHAAERmOAAIjOA="
)
H264_SECOND_FRAME = base64.b64decode(
    "AAAAAWdCwArd6EAAAAMAQAAAB6PEieAAAAABaM4PyAAAAWWIggJoRigACmXHAAElOOAAJKeA"
)
H265_KEYFRAME = base64.b64decode(
    "AAAAAUABDAH//wQIAAADAJ+oAAADAAAeugJAAAAAAUIBAQQIAAADAJ+oAAADAAAeoCCBBZbpKTC5o"
    "CAAAAMAIAAAAwHhAAAAAUQBwHGBEgAAASgBreDHp//PUf/7NZP+DiD7y/g="
)
SYNTHETIC_PAYLOAD = b"synthetic-video-frame"


def _frame(data: bytes) -> VideoFrame:
    return VideoFrame(0, 1, "H264", 15.0, 16, 16, data)


def test_bridge_remuxes_without_changing_codec_and_adds_timestamps() -> None:
    first = _frame(H264_KEYFRAME)
    muxer = _MpegTsMuxer(first)
    payload = muxer.mux(first) + muxer.mux(_frame(H264_SECOND_FRAME))
    muxer.close()

    container = av.open(io.BytesIO(payload), format="mpegts")
    try:
        video = container.streams.video[0]
        packets = [packet for packet in container.demux(video) if packet.size]
    finally:
        container.close()

    assert video.codec_context.name == "h264"
    assert [packet.dts for packet in packets] == [0, 6000]
    assert all(packet.pts is not None for packet in packets)


def test_bridge_remuxes_synthetic_h265_without_transcoding() -> None:
    frame = VideoFrame(0, 1, "H265", 15.0, 64, 64, H265_KEYFRAME)
    muxer = _MpegTsMuxer(frame)
    payload = muxer.mux(frame)
    muxer.close()

    container = av.open(io.BytesIO(payload), format="mpegts")
    try:
        video = container.streams.video[0]
        packet = next(packet for packet in container.demux(video) if packet.size)
    finally:
        container.close()

    assert video.codec_context.name == "hevc"
    assert packet.dts == 0
    assert packet.pts == 0


class _PassThroughMuxer:
    def __init__(self, first_frame: VideoFrame) -> None:
        del first_frame

    def mux(self, frame: VideoFrame) -> bytes:
        return frame.data

    def close(self) -> None:
        return


class _FakeLiveStream:
    behavior = "hold"
    instances: list[_FakeLiveStream] = []
    release: asyncio.Event | None = None
    active_by_channel: Counter[int] = Counter()
    max_by_channel: Counter[int] = Counter()

    @classmethod
    def reset(cls) -> None:
        cls.behavior = "hold"
        cls.instances = []
        cls.release = None
        cls.active_by_channel = Counter()
        cls.max_by_channel = Counter()

    def __init__(
        self,
        session: object,
        host: str,
        port: int,
        username: str,
        password: str,
        channel: int,
        stream_id: int,
    ) -> None:
        del session, host, port, username, stream_id
        self.password = password
        self.channel = channel
        self.exited = False
        type(self).instances.append(self)

    async def __aenter__(self) -> _FakeLiveStream:
        cls = type(self)
        cls.active_by_channel[self.channel] += 1
        cls.max_by_channel[self.channel] = max(
            cls.max_by_channel[self.channel], cls.active_by_channel[self.channel]
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        del args
        type(self).active_by_channel[self.channel] -= 1
        self.exited = True

    async def async_frames(self):  # type: ignore[no-untyped-def]
        if self.behavior == "no_frame":
            raise Kp2pError(f"synthetic no-frame failure {self.password}")
        yield VideoFrame(0, 1, "H264", 15.0, 16, 16, SYNTHETIC_PAYLOAD)
        if self.behavior == "disconnect":
            raise Kp2pError(f"synthetic disconnect {self.password}")
        release = type(self).release
        assert release is not None
        await release.wait()
        yield VideoFrame(0, 1, "H264", 15.0, 16, 16, SYNTHETIC_PAYLOAD)


@pytest.fixture
def fake_stream_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeLiveStream.reset()
    _FakeLiveStream.release = asyncio.Event()
    monkeypatch.setattr("custom_components.jooan_nvr.bridge.Kp2pLiveStream", _FakeLiveStream)
    monkeypatch.setattr("custom_components.jooan_nvr.bridge._MpegTsMuxer", _PassThroughMuxer)


def _bridge(channel: int = 0, password: str = "private-test-password") -> StreamBridge:
    return StreamBridge(MagicMock(), "192.168.77.10", 10000, "admin", password, channel, 1)


async def _connect(
    bridge: StreamBridge,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    port = int(bridge.source_url.rsplit(":", 1)[1])
    return await asyncio.open_connection("127.0.0.1", port)


async def _wait_until(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(1):
        while not predicate():
            await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_listener_is_loopback_credential_free_and_restartable(
    fake_stream_transport: None,
) -> None:
    del fake_stream_transport
    bridge = _bridge()

    for _ in range(3):
        await bridge.async_start()
        assert bridge.source_url.startswith("tcp://127.0.0.1:")
        assert "admin" not in bridge.source_url
        assert "private-test-password" not in bridge.source_url
        assert bridge._server is not None  # noqa: SLF001
        assert bridge._server.sockets[0].getsockname()[0] == "127.0.0.1"  # noqa: SLF001
        await bridge.async_stop()
        assert not bridge._tasks  # noqa: SLF001
        with pytest.raises(RuntimeError, match="not running"):
            _ = bridge.source_url


@pytest.mark.asyncio
async def test_nvr_disconnect_and_no_first_frame_clean_up_without_secret_logs(
    fake_stream_transport: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    del fake_stream_transport
    caplog.set_level(logging.DEBUG, logger="custom_components.jooan_nvr.bridge")
    secret = "must-not-appear-in-logs"

    for behavior in ("disconnect", "no_frame"):
        _FakeLiveStream.behavior = behavior
        bridge = _bridge(password=secret)
        await bridge.async_start()
        reader, writer = await _connect(bridge)
        await asyncio.wait_for(reader.read(), timeout=1)
        await _wait_until(lambda bridge=bridge: not bridge._tasks)  # noqa: B023, SLF001
        writer.close()
        await writer.wait_closed()
        await bridge.async_stop()

    assert all(instance.exited for instance in _FakeLiveStream.instances)
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_consumer_disconnect_releases_connection(
    fake_stream_transport: None,
) -> None:
    del fake_stream_transport
    bridge = _bridge()
    await bridge.async_start()
    reader, writer = await _connect(bridge)
    assert (
        await asyncio.wait_for(reader.readexactly(len(SYNTHETIC_PAYLOAD)), timeout=1)
        == SYNTHETIC_PAYLOAD
    )

    writer.transport.abort()
    assert _FakeLiveStream.release is not None
    _FakeLiveStream.release.set()
    await _wait_until(lambda: not bridge._tasks)  # noqa: SLF001
    await bridge.async_stop()

    assert _FakeLiveStream.active_by_channel[0] == 0
    assert _FakeLiveStream.instances[0].exited


@pytest.mark.asyncio
async def test_simultaneous_consumers_and_two_cameras_stop_cleanly(
    fake_stream_transport: None,
) -> None:
    del fake_stream_transport
    first = _bridge(channel=0)
    second = _bridge(channel=1)
    await first.async_start()
    await second.async_start()
    connections = [await _connect(first), await _connect(first), await _connect(second)]
    await _wait_until(lambda: len(_FakeLiveStream.instances) == 3)

    for reader, _ in connections:
        assert (
            await asyncio.wait_for(reader.readexactly(len(SYNTHETIC_PAYLOAD)), timeout=1)
            == SYNTHETIC_PAYLOAD
        )
    assert _FakeLiveStream.max_by_channel == Counter({0: 2, 1: 1})

    await asyncio.wait_for(first.async_stop(), timeout=2)
    await asyncio.wait_for(second.async_stop(), timeout=2)
    for _, writer in connections:
        writer.close()
        with suppress(ConnectionError):
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
    assert not first._tasks  # noqa: SLF001
    assert not second._tasks  # noqa: SLF001
    assert not any(_FakeLiveStream.active_by_channel.values())
    assert all(instance.exited for instance in _FakeLiveStream.instances)
