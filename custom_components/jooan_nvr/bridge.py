"""On-demand loopback bridge from KP2P framing to timestamped MPEG-TS."""

from __future__ import annotations

import asyncio
import io
import logging
import re
from collections.abc import Callable
from contextlib import suppress
from fractions import Fraction

import av
from aiohttp import ClientSession

from .kp2p import Kp2pError, Kp2pLiveStream, VideoFrame

_LOGGER = logging.getLogger(__name__)

MPEG_TS_TIME_BASE = Fraction(1, 90_000)
WRITER_CLOSE_TIMEOUT = 1.0
ERROR_MESSAGE_LIMIT = 300

_SENSITIVE_FIELD = re.compile(
    r"(?i)\b(?:authorization|basic|password|passwd|username|user|uid|hwid|auth[_ -]?payload)"
    r"\s*[:=]\s*[^\s,;)}]+"
)
_BASIC_AUTH = re.compile(r"(?i)\b(?:authorization\s*[:=]\s*)?basic\s+[A-Za-z0-9+/=._~-]+")
_URL_CREDENTIALS = re.compile(r"(?i)(?:https?|wss?)://[^/@\s]+@")


def _sanitise_exception_message(error: BaseException, secrets: tuple[str, ...]) -> str:
    """Return a bounded exception message with known credentials removed."""
    message = str(error).replace("\r", " ").replace("\n", " ")
    for secret in secrets:
        if secret:
            message = re.sub(re.escape(secret), "<redacted>", message, flags=re.IGNORECASE)
    message = _URL_CREDENTIALS.sub("<redacted-url-credentials>@", message)
    message = _BASIC_AUTH.sub("<redacted-basic-authorization>", message)
    message = _SENSITIVE_FIELD.sub("<redacted>", message)
    return message[:ERROR_MESSAGE_LIMIT] or "no details"


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
    def _stream_name(self) -> str:
        return {0: "main", 1: "sub"}.get(self._stream_id, "unknown")

    def _debug(self, stage: str, error: BaseException | None = None) -> None:
        """Log a safe, channel-scoped lifecycle event at DEBUG level."""
        context = f"Channel {self._channel + 1} stream {self._stream_id} ({self._stream_name})"
        if error is None:
            _LOGGER.debug("%s: %s", context, stage)
            return
        message = _sanitise_exception_message(
            error,
            (self._username, self._password),
        )
        _LOGGER.debug(
            "%s: failure at %s (%s: %s)",
            context,
            stage,
            type(error).__name__,
            message,
        )

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
        try:
            self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        except OSError as err:
            self._debug("loopback listener starting", err)
            raise
        self._debug("loopback listener started")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task:
            self._tasks.add(task)
        muxer: _MpegTsMuxer | None = None
        stage = "Home Assistant connected to loopback listener"
        first_video_frame = False
        first_keyframe = False
        first_bytes = False
        try:
            if self._stopping:
                return
            self._debug(stage)
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
                    stage_callback=self._debug,
                ) as stream,
            ):
                stage = "waiting for first video frame"
                async for frame in stream.async_frames():
                    if not first_video_frame:
                        first_video_frame = True
                        self._debug("first video frame received")
                    if muxer is None:
                        if frame.frame_type != 1:
                            stage = "waiting for first keyframe"
                            continue
                        first_keyframe = True
                        self._debug("first keyframe received")
                        stage = "PyAV input parser"
                        muxer = await asyncio.to_thread(_MpegTsMuxer, frame)
                        self._debug("muxer created")
                    stage = "MPEG-TS mux"
                    payload = await asyncio.to_thread(muxer.mux, frame)
                    writer.write(payload)
                    stage = "writing MPEG-TS to Home Assistant"
                    await asyncio.wait_for(writer.drain(), timeout=5)
                    if payload and not first_bytes:
                        first_bytes = True
                        self._debug("first MPEG-TS bytes written")
                    if reader.at_eof():
                        self._debug("Home Assistant consumer disconnected")
                        break
                if not first_video_frame:
                    raise Kp2pError("stream ended before a video frame", stage="no video frames")
                if not first_keyframe:
                    raise Kp2pError("stream ended before a keyframe", stage="no keyframe")
        except (ConnectionError, TimeoutError, Kp2pError, OSError, av.FFmpegError) as err:
            failure_stage = err.stage if isinstance(err, Kp2pError) and err.stage else stage
            if isinstance(err, (BrokenPipeError, ConnectionResetError)):
                failure_stage = "Home Assistant consumer disconnected"
            self._debug(failure_stage, err)
        finally:
            if muxer:
                await asyncio.to_thread(muxer.close)
            writer.close()
            with suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), WRITER_CLOSE_TIMEOUT)
            if task:
                self._tasks.discard(task)
            self._debug("loopback client stopped")

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
        self._debug("bridge stopped")


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
