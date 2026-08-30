"""On-demand loopback bridge from KP2P framing to timestamped MPEG-TS."""

from __future__ import annotations

import asyncio
import io
import logging
from collections.abc import Callable
from contextlib import suppress
from fractions import Fraction

import av
from aiohttp import ClientSession

from .kp2p import Kp2pError, Kp2pLiveStream, VideoFrame

_LOGGER = logging.getLogger(__name__)

MPEG_TS_TIME_BASE = Fraction(1, 90_000)
WRITER_CLOSE_TIMEOUT = 1.0


class _MpegTsMuxer:
    """Add synthetic timestamps and MPEG-TS framing without transcoding video."""

    def __init__(self, first_frame: VideoFrame) -> None:
        codec = (first_frame.codec or "").lower()
        if "265" in codec or "hevc" in codec:
            input_format = "hevc"
        elif "264" in codec or "avc" in codec:
            input_format = "h264"
        else:
            raise Kp2pError(f"unsupported local video codec: {first_frame.codec}")

        self._buffer = io.BytesIO()
        self._template = av.open(io.BytesIO(first_frame.data), format=input_format)
        self._output = av.open(self._buffer, mode="w", format="mpegts")
        try:
            self._stream = self._output.add_stream_from_template(self._template.streams.video[0])
        except av.FFmpegError, IndexError:
            with suppress(av.FFmpegError):
                self._output.close()
            self._template.close()
            raise
        self._stream.time_base = MPEG_TS_TIME_BASE
        self._timestamp = 0

    def mux(self, frame: VideoFrame) -> bytes:
        """Wrap one unchanged encoded frame in timestamped MPEG-TS packets."""
        frame_rate = frame.frame_rate or 15.0
        duration = max(round(90_000 / frame_rate), 1)
        packet = av.Packet(frame.data)
        packet.stream = self._stream
        packet.time_base = MPEG_TS_TIME_BASE
        packet.pts = packet.dts = self._timestamp
        packet.duration = duration
        self._timestamp += duration
        self._output.mux(packet)
        return self._drain()

    def _drain(self) -> bytes:
        payload = self._buffer.getvalue()
        self._buffer.seek(0)
        self._buffer.truncate()
        return payload

    def close(self) -> None:
        """Release the in-memory FFmpeg muxing contexts."""
        with suppress(av.FFmpegError):
            self._output.close()
        self._template.close()


class StreamBridge:
    """Expose one channel/quality as an FFmpeg-readable loopback TCP source."""

    def __init__(
        self,
        session: ClientSession,
        host: str,
        kp2p_port: int,
        username: str,
        password: str,
        channel: int,
        stream_id: int,
    ) -> None:
        self._session = session
        self._host = host
        self._kp2p_port = kp2p_port
        self._username = username
        self._password = password
        self._channel = channel
        self._stream_id = stream_id
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._slots = asyncio.Semaphore(2)
        self._stopping = False

    @property
    def source_url(self) -> str:
        """Return the local source URL after startup."""
        if self._server is None or not self._server.sockets:
            raise RuntimeError("stream bridge is not running")
        port = self._server.sockets[0].getsockname()[1]
        return f"tcp://127.0.0.1:{port}"

    async def async_start(self) -> None:
        """Start a loopback-only listener without opening the camera stream."""
        if self._server is not None:
            return
        self._stopping = False
        self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        del reader
        task = asyncio.current_task()
        if task:
            self._tasks.add(task)
        muxer: _MpegTsMuxer | None = None
        try:
            if self._stopping:
                return
            async with (
                self._slots,
                Kp2pLiveStream(
                    self._session,
                    self._host,
                    self._kp2p_port,
                    self._username,
                    self._password,
                    self._channel,
                    self._stream_id,
                ) as stream,
            ):
                async for frame in stream.async_frames():
                    if muxer is None:
                        if frame.frame_type != 1:
                            continue
                        muxer = _MpegTsMuxer(frame)
                    writer.write(muxer.mux(frame))
                    await asyncio.wait_for(writer.drain(), timeout=5)
        except (ConnectionError, TimeoutError, Kp2pError, OSError, av.FFmpegError) as err:
            _LOGGER.debug(
                "Channel %s stream bridge closed (%s)",
                self._channel + 1,
                type(err).__name__,
            )
        finally:
            if muxer:
                muxer.close()
            writer.close()
            with suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), WRITER_CLOSE_TIMEOUT)
            if task:
                self._tasks.discard(task)

    async def async_stop(self) -> None:
        """Close the listener and any active on-demand streams."""
        self._stopping = True
        if server := self._server:
            self._server = None
            server.close()
            # Python 3.14 waits for active client handlers in wait_closed(), so
            # stop those handlers before awaiting the listener's final close.
            await asyncio.sleep(0)
        while self._tasks:
            tasks = tuple(self._tasks)
            self._tasks.difference_update(tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if server:
            await server.wait_closed()


class StreamBridgeManager:
    """Lazily own the loopback bridges for one config entry."""

    def __init__(
        self,
        bridge_factory: Callable[[int, int], StreamBridge],
        stream_id: int,
    ) -> None:
        self._bridge_factory = bridge_factory
        self._stream_id = stream_id
        self._bridges: dict[int, StreamBridge] = {}
        self._lock = asyncio.Lock()

    async def async_source_url(self, channel: int) -> str:
        """Create a channel listener on first use and return its URL."""
        async with self._lock:
            if channel not in self._bridges:
                bridge = self._bridge_factory(channel, self._stream_id)
                await bridge.async_start()
                self._bridges[channel] = bridge
            return self._bridges[channel].source_url

    async def async_stop(self) -> None:
        """Stop all channel bridges."""
        bridges = tuple(self._bridges.values())
        self._bridges.clear()
        await asyncio.gather(*(bridge.async_stop() for bridge in bridges))
