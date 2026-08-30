"""Local KP2P transport used by the recorder's built-in web client."""

from __future__ import annotations

import asyncio
import secrets
import struct
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from types import TracebackType
from typing import Self

from aiohttp import ClientError, ClientSession, ClientWebSocketResponse, WSMsgType
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ARQ_OPEN = bytes.fromhex("d9ffcc028c38eed2d199ac6026947fae")
ARQ_OPEN_RESPONSE = bytes.fromhex("96d5390d12fcbe8f4790d932ccd849f3")
ARQ_DATA = bytes.fromhex("cefaeffe")
IOT_MAGIC = bytes.fromhex("abbccdde")
API_MAGIC = 0x4B503250
FRAME_MAGIC = 0x4652414D
FRAME_MAGIC2 = 0x4652414E
# Fixed wire-format compatibility constant, not a device/account credential. The
# recorder still authenticates the user-supplied local username and password.
AUTH_FIELD_CIPHER_KEY = b"~!JUAN*&Vision-="

IOT_PING = 17
IOT_OPEN_REQ = 20
IOT_OPEN_RES = 21
IOT_DATA = 19
IOT_DATA_PRIOR = 43
API_AUTH_REQ = 10
API_AUTH_RSP = 11
API_LIVE_REQ = 30
API_LIVE_RSP = 31
LIVE_STOP = 1
LIVE_START = 2
CLOSE_TIMEOUT = 1.0


class Kp2pError(Exception):
    """Base local KP2P error."""

    def __init__(self, message: str, *, stage: str | None = None) -> None:
        super().__init__(message)
        self.stage = stage


class Kp2pAuthenticationError(Kp2pError):
    """The recorder rejected KP2P authentication."""


@dataclass(frozen=True, slots=True)
class VideoFrame:
    """One video frame with its Annex-B elementary-stream payload."""

    channel: int
    frame_type: int
    codec: str | None
    frame_rate: float | None
    width: int | None
    height: int | None
    data: bytes


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _iot_packet(command: int, sid: int, payload: bytes, *, error_code: int = 0) -> bytes:
    header = bytearray(32)
    header[0:4] = IOT_MAGIC
    struct.pack_into("<I", header, 4, command)
    header[8:12] = b"\x00\x00\x00\x01"
    struct.pack_into("<I", header, 16, sid)
    struct.pack_into("<i", header, 24, error_code)
    struct.pack_into("<I", header, 28, len(payload))
    return bytes(header) + payload


def _api_packet(command: int, ticket: int, payload: bytes, *, result: int = 0) -> bytes:
    return struct.pack("<IIIIiI", API_MAGIC, 1, ticket, command, result, len(payload)) + payload


def _encrypt_field(value: str) -> bytes:
    encoded = value.encode()
    if len(encoded) >= 32:
        raise Kp2pError("KP2P credentials must be shorter than 32 UTF-8 bytes")
    encryptor = Cipher(algorithms.AES(AUTH_FIELD_CIPHER_KEY), modes.ECB()).encryptor()
    return encryptor.update(encoded.ljust(32, b"\0")) + encryptor.finalize()


def _auth_payload(username: str, password: str) -> bytes:
    return _encrypt_field(username) + _encrypt_field(password)


def _live_payload(channel: int, stream_id: int, command: int) -> bytes:
    return struct.pack("<III", channel, stream_id, command)


def _parse_api(data: bytes) -> tuple[int, int, bytes]:
    if len(data) < 24 or _u32(data, 0) != API_MAGIC:
        raise Kp2pError("invalid KP2P API packet")
    command = _u32(data, 12)
    result = _i32(data, 16)
    size = _u32(data, 20)
    if size > len(data) - 24:
        raise Kp2pError("truncated KP2P API payload")
    return command, result, data[24 : 24 + size]


def _parse_video_frame(data: bytes) -> VideoFrame | None:
    """Extract metadata and the proven Annex-B H.265/H.264 frame payload."""
    if len(data) < 64:
        return None
    offset = 0
    magic = _u32(data, offset)
    if magic == FRAME_MAGIC2:
        if len(data) < 104:
            return None
        offset = 40
        magic = _u32(data, offset)
    if magic != FRAME_MAGIC or len(data) < offset + 64:
        return None
    if _u32(data, offset + 8) != 0:  # live frames only
        return None
    frame_type = _u32(data, offset + 24)
    if frame_type not in {1, 2}:  # I-frame or P-frame; audio is not mixed into raw video
        return None
    channel = _u32(data, offset + 28)
    parameters = offset + 32
    codec = data[parameters : parameters + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
    frame_rate = _u32(data, parameters + 8)
    width = _u32(data, parameters + 12)
    height = _u32(data, parameters + 16)
    return VideoFrame(
        channel=channel,
        frame_type=frame_type,
        codec=codec or None,
        frame_rate=float(frame_rate) if frame_rate else None,
        width=width or None,
        height=height or None,
        data=data[offset + 64 :],
    )


class _Session:
    def __init__(self, websocket: ClientWebSocketResponse, sid: int, timeout: float) -> None:
        self.websocket = websocket
        self.sid = sid
        self.timeout = timeout
        self.ticket = 0
        self._send_lock = asyncio.Lock()

    async def send_iot(self, command: int, payload: bytes) -> None:
        packet = _iot_packet(command, self.sid, payload)
        async with self._send_lock:
            await self.websocket.send_bytes(ARQ_DATA + struct.pack("<I", len(packet)))
            await self.websocket.send_bytes(packet)

    async def send_api(self, command: int, payload: bytes) -> None:
        self.ticket += 1
        await self.send_iot(IOT_DATA, _api_packet(command, self.ticket, payload))

    async def receive_iot(self, timeout: float | None = None) -> tuple[int, int, bytes]:
        deadline = asyncio.get_running_loop().time() + (timeout or self.timeout)
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise Kp2pError("timed out waiting for KP2P data")
            message = await asyncio.wait_for(self.websocket.receive(), remaining)
            if message.type is WSMsgType.TEXT:
                continue
            if message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING}:
                raise Kp2pError("KP2P WebSocket closed")
            if message.type is WSMsgType.ERROR:
                error = self.websocket.exception()
                if error is None:
                    raise Kp2pError("KP2P WebSocket error")
                raise Kp2pError("KP2P WebSocket error") from error
            if message.type is not WSMsgType.BINARY:
                continue
            data = bytes(message.data)
            if data.startswith(ARQ_DATA):
                continue
            if len(data) < 32 or not data.startswith(IOT_MAGIC):
                continue
            command = _u32(data, 4)
            error_code = _i32(data, 24)
            size = _u32(data, 28)
            if size > len(data) - 32:
                raise Kp2pError("truncated IOT payload")
            return command, error_code, data[32 : 32 + size]

    async def receive_api_or_frame(self, timeout: float | None = None) -> tuple[str, object]:
        deadline = asyncio.get_running_loop().time() + (timeout or self.timeout)
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise Kp2pError("timed out waiting for KP2P API or video data")
            command, error_code, payload = await self.receive_iot(remaining)
            if command not in {IOT_DATA, IOT_DATA_PRIOR}:
                continue
            if error_code:
                raise Kp2pError(f"IOT error {error_code}")
            if len(payload) >= 4 and _u32(payload, 0) == API_MAGIC:
                return "api", _parse_api(payload)
            if frame := _parse_video_frame(payload):
                return "frame", frame

    async def authenticate(self, username: str, password: str) -> None:
        await self.send_api(API_AUTH_REQ, _auth_payload(username, password))
        while True:
            kind, value = await self.receive_api_or_frame()
            if kind != "api":
                continue
            command, result, _ = value  # type: ignore[misc]
            if command != API_AUTH_RSP:
                continue
            if result != 0:
                raise Kp2pAuthenticationError(f"KP2P authentication failed ({result})")
            return

    async def open_stream(self, channel: int, stream_id: int) -> None:
        await self.send_api(API_LIVE_REQ, _live_payload(channel, stream_id, LIVE_START))
        while True:
            kind, value = await self.receive_api_or_frame()
            if kind != "api":
                continue
            command, result, payload = value  # type: ignore[misc]
            if command != API_LIVE_RSP or len(payload) < 12:
                continue
            response_channel, response_stream, live_command = struct.unpack_from("<III", payload)
            if (response_channel, response_stream, live_command) != (
                channel,
                stream_id,
                LIVE_START,
            ):
                continue
            if result != 0:
                raise Kp2pError(f"open stream failed ({result})")
            return


class Kp2pLiveStream:
    """One on-demand recorder stream connection."""

    def __init__(
        self,
        session: ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        channel: int,
        stream_id: int,
        *,
        timeout: float = 6.0,
        stage_callback: Callable[[str], None] | None = None,
    ) -> None:
        self._http_session = session
        self._endpoint = f"ws://{host}:{port}"
        self._username = username
        self._password = password
        self._channel = channel
        self._stream_id = stream_id
        self._timeout = timeout
        self._stage_callback = stage_callback
        self._websocket: ClientWebSocketResponse | None = None
        self._session: _Session | None = None
        self._keepalive_task: asyncio.Task[None] | None = None

    def _stage(self, stage: str) -> None:
        """Report a credential-free lifecycle stage to the bridge."""
        if self._stage_callback:
            self._stage_callback(stage)

    async def __aenter__(self) -> Self:
        sid = secrets.randbelow(9999) + 1
        stage = "KP2P websocket connecting"
        try:
            self._stage(stage)
            websocket = await self._http_session.ws_connect(
                self._endpoint,
                autoping=False,
                heartbeat=None,
                max_msg_size=8 * 1024 * 1024,
                timeout=self._timeout,
            )
            self._websocket = websocket
            self._stage("KP2P websocket connected")
            stage = "ARQ handshake"
            await websocket.send_bytes(ARQ_OPEN + struct.pack("<I", sid))
            response = await asyncio.wait_for(websocket.receive(), self._timeout)
            if response.type is not WSMsgType.BINARY or bytes(response.data) != ARQ_OPEN_RESPONSE:
                raise Kp2pError("ARQ connection handshake was rejected")
            protocol = _Session(websocket, sid, self._timeout)
            self._session = protocol
            await protocol.send_iot(IOT_OPEN_REQ, struct.pack("<II", sid, 0))
            while True:
                command, error_code, _ = await protocol.receive_iot()
                if command != IOT_OPEN_RES:
                    continue
                if error_code:
                    raise Kp2pError(f"IOT open failed ({error_code})")
                break
            self._stage("ARQ handshake complete")
            stage = "KP2P authentication"
            await protocol.authenticate(self._username, self._password)
            self._stage("KP2P authentication complete")
            stage = "live-stream request"
            await protocol.open_stream(self._channel, self._stream_id)
            self._stage("live-stream request accepted")
            self._keepalive_task = asyncio.create_task(
                self._keepalive(), name=f"jooan-kp2p-{self._channel}"
            )
            return self
        except (TimeoutError, ClientError, OSError) as err:
            await self.async_close()
            raise Kp2pError("could not open the local KP2P stream", stage=stage) from err
        except Kp2pError as err:
            await self.async_close()
            if err.stage is None:
                err.stage = stage
            raise
        except Exception:
            await self.async_close()
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.async_close()

    async def _keepalive(self) -> None:
        assert self._session is not None
        try:
            while True:
                await asyncio.sleep(8)
                payload = str(self._session.sid).encode().ljust(96, b"\0")
                await self._session.send_iot(IOT_PING, payload)
        except asyncio.CancelledError:
            raise

    async def async_frames(self):  # type: ignore[no-untyped-def]
        """Yield raw video frames until the consumer disconnects."""
        if self._session is None:
            raise Kp2pError("stream is not open")
        while True:
            kind, value = await self._session.receive_api_or_frame(timeout=15)
            if kind != "frame":
                continue
            frame = value
            if isinstance(frame, VideoFrame) and frame.channel == self._channel and frame.data:
                yield frame

    async def async_close(self) -> None:
        """Stop the live command and close the local WebSocket."""
        if self._keepalive_task:
            self._keepalive_task.cancel()
            await asyncio.gather(self._keepalive_task, return_exceptions=True)
            self._keepalive_task = None
        if protocol := self._session:
            self._session = None
            with suppress(TimeoutError, ClientError, Kp2pError, OSError):
                await asyncio.wait_for(
                    protocol.send_api(
                        API_LIVE_REQ,
                        _live_payload(self._channel, self._stream_id, LIVE_STOP),
                    ),
                    CLOSE_TIMEOUT,
                )
        if websocket := self._websocket:
            self._websocket = None
            with suppress(TimeoutError, ClientError, OSError):
                await asyncio.wait_for(websocket.close(), CLOSE_TIMEOUT)


__all__ = [
    "Kp2pAuthenticationError",
    "Kp2pError",
    "Kp2pLiveStream",
    "VideoFrame",
]
